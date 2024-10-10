use address::Address;
use rkyv::{Archive, Archived};
use tree_bitmap::node::ArchivedNode;
use tree_bitmap::{
    allocator::{choose_bucket, AllocatorHandle, ArchivedAllocator, ArchivedBucketVec},
    node::Node,
    ArchivedTreeBitmap, TrieAccess,
};
use ArchivedIpLookupTable;

impl<A: Address, T: Archive + Clone + Copy + Default> ArchivedIpLookupTable<A, T> {
    /// Return number of items inside table.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if no item is inside table.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Longest match lookup of `ip`
    pub fn longest_match(&self, ip: A) -> Option<(A, u32, &Archived<T>)> {
        match self.inner.longest_match(&ip.nibbles().as_ref()) {
            Some((bits_matched, value)) => Some((ip.mask(bits_matched), bits_matched, value)),
            None => None,
        }
    }

    /// Perform exact match lookup of `ip` and `masklen` and return the value.
    pub fn exact_match(&self, ip: A, masklen: u32) -> Option<&Archived<T>> {
        self.inner.exact_match(&ip.nibbles().as_ref(), masklen)
    }
}

impl<T: Archive + Clone + Copy + Default> ArchivedTreeBitmap<T> {
    /// Return number of items inside table.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Longest match lookup of `nibbles`. Returns bits matched as u32, and reference to T.
    pub fn longest_match(&self, nibbles: &[u8]) -> Option<(u32, &Archived<T>)> {
        match self.longest_match_internal(&nibbles) {
            Some((result_hdl, result_index, bits_matched)) => {
                Some((bits_matched, self.results.get(&result_hdl, result_index)))
            }
            None => None,
        }
    }

    /// Perform exact match lookup of `nibbles` and `masklen` and return the value.
    pub fn exact_match(&self, nibbles: &[u8], masklen: u32) -> Option<&Archived<T>> {
        self.exact_match_internal(nibbles, masklen)
            .map(|(result_hdl, result_index)| self.results.get(&result_hdl, result_index))
    }
}

impl<T: Archive + Clone + Copy + Default> TrieAccess for ArchivedTreeBitmap<T> {
    fn get_node(&self, hdl: &AllocatorHandle, index: u32) -> Node {
        Node::from(self.trienodes.get(&hdl, index))
    }
}

impl<T: Archive + Clone + Copy + Default> ArchivedAllocator<T> {
    #[inline]
    pub fn get(&self, hdl: &AllocatorHandle, index: u32) -> &Archived<T> {
        let bucket_index = choose_bucket(hdl.len) as usize;
        self.buckets[bucket_index].get_slot_entry(hdl.offset, index)
    }
}

impl<T: Archive + Clone + Copy + Default> ArchivedBucketVec<T> {
    #[inline]
    pub fn get_slot_entry(&self, slot: u32, index: u32) -> &Archived<T> {
        debug_assert!(slot % self.spacing == 0);
        let offset = (slot + index) as usize;
        &self.buf[offset]
    }
}

impl From<&ArchivedNode> for Node {
    fn from(v: &ArchivedNode) -> Self {
        Node {
            bitmap: v.bitmap,
            child_ptr: v.child_ptr,
            result_ptr: v.result_ptr,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use IpLookupTable;

    #[test]
    fn test_rkyv() {
        let mut table = IpLookupTable::new();
        let less_specific = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let more_specific = Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0, 0, 0, 0, 0);
        table.insert(less_specific, 32, 123);
        table.insert(more_specific, 48, 321);

        let ip_1 = Ipv6Addr::new(0x2001, 0xdb8, 0xdead, 0xbeef, 0xcafe, 0xbabe, 0, 1);
        assert_eq!(table.longest_match(ip_1), Some((more_specific, 48, &321)));
        assert_eq!(table.exact_match(ip_1, 48), Some(&321));

        let ip_2 = Ipv6Addr::new(0x2001, 0xdb8, 0xcafe, 0xf00, 0xf00, 0xf00, 0, 1);
        assert_eq!(table.longest_match(ip_2), Some((less_specific, 32, &123)));
        rkyv::to_bytes::<_, 1024>(&table).unwrap();

        #[cfg(feature = "bytecheck")]
        {
            let rkyv_bytes = rkyv::to_bytes::<_, 1024>(&table).unwrap();
            let rkyv_table =
                rkyv::check_archived_root::<IpLookupTable<Ipv6Addr, i32>>(&rkyv_bytes).unwrap();

            assert!(!rkyv_table.is_empty());
            assert_eq!(rkyv_table.len(), 2);

            assert_eq!(rkyv_table.exact_match(ip_1, 48), Some(&321));
            assert_eq!(
                rkyv_table.longest_match(ip_1),
                Some((more_specific, 48, &321))
            );
            assert_eq!(
                rkyv_table.longest_match(ip_2),
                Some((less_specific, 32, &123))
            );
        }
    }
}
