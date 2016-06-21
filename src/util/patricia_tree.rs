// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Patricia/Radix Trie 
//!
//! A Patricia trie is a trie in which nodes with only one child are
//! merged with the child, giving huge space savings for sparse tries.
//! A radix tree is more general, working with keys that are arbitrary
//! strings; a Patricia tree uses bitstrings.
//!

use std::fmt::Debug;
use std::marker;
use std::{cmp, fmt, ops, ptr};
use num::{Zero, One};

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleDecoder, SimpleEncoder};
use util::BitArray;

/// Patricia troo
pub struct PatriciaTree<K: Copy, V> {
    data: Option<V>,
    child_l: Option<Box<PatriciaTree<K, V>>>,
    child_r: Option<Box<PatriciaTree<K, V>>>,
    skip_prefix: K,
    skip_len: u8
}

impl<K, V> PatriciaTree<K, V>
    where K: Copy + BitArray + cmp::Eq + Zero + One +
             ops::BitXor<K, Output=K> +
             ops::Add<K, Output=K> +
             ops::Shr<usize, Output=K> +
             ops::Shl<usize, Output=K>
{
    /// Constructs a new Patricia tree
    pub fn new() -> PatriciaTree<K, V> {
        PatriciaTree {
            data: None,
            child_l: None,
            child_r: None,
            skip_prefix: Zero::zero(),
            skip_len: 0
        }
    }

    /// Lookup a value by exactly matching `key` and return a referenc
    pub fn lookup_mut(&mut self, key: &K, key_len: usize) -> Option<&mut V> {
        // Caution: `lookup_mut` never modifies its self parameter (in fact its
        // internal recursion uses a non-mutable self, so we are OK to just
        // transmute our self pointer into a mutable self before passing it in.
        use std::mem::transmute;
        unsafe { transmute(self.lookup(key, key_len)) }
    }

    /// Lookup a value by exactly matching `key` and return a mutable reference
    pub fn lookup(&self, key: &K, key_len: usize) -> Option<&V> {
        let mut node = self;
        let mut key_idx = 0;

        loop {
            // If the search key is shorter than the node prefix, there is no
            // way we can match, so fail.
            if key_len - key_idx < node.skip_len as usize {
                return None;
            }

            // Key fails to match prefix --- no match
            if node.skip_prefix != key.bit_slice(key_idx, key_idx + node.skip_len as usize) {
                return None;
            }

            // Key matches prefix: if they are an exact match, return the data
            if node.skip_len as usize == key_len - key_idx {
                return node.data.as_ref();
            } else {
                // Key matches prefix: search key longer than node key, recurse
                key_idx += 1 + node.skip_len as usize;
                let subtree = if key.bit(key_idx - 1) { &node.child_r } else { &node.child_l };
                match *subtree {
                    Some(ref bx) => {
                        node = &**bx;    // bx is a &Box<U> here, so &**bx gets &U
                    }
                    None => { return None; }
                }
            }
        } // end loop
    }

    /// Inserts a value with key `key`, returning true on success. If a value is already
    /// stored against `key`, do nothing and return false.
    #[inline]
    pub fn insert(&mut self, key: &K, key_len: usize, value: V) -> bool {
        self.real_insert(key, key_len, value, false)
    }

    /// Inserts a value with key `key`, returning true on success. If a value is already
    /// stored against `key`, overwrite it and return false.
    #[inline]
    pub fn insert_or_update(&mut self, key: &K, key_len: usize, value: V) -> bool {
        self.real_insert(key, key_len, value, true)
    }

    fn real_insert(&mut self, key: &K, key_len: usize, value: V, overwrite: bool) -> bool {
        let mut node = self;
        let mut idx = 0;
        loop {
            // Mask in case search key is shorter than node key
            let slice_len = cmp::min(node.skip_len as usize, key_len - idx);
            let masked_prefix = node.skip_prefix.mask(slice_len);
            let key_slice = key.bit_slice(idx, idx + slice_len);

            // Prefixes do not match: split key
            if masked_prefix != key_slice {
                let diff = (masked_prefix ^ key_slice).trailing_zeros();

                // Remove the old node's children
                let child_l = node.child_l.take();
                let child_r = node.child_r.take();
                let value_neighbor = node.data.take();
                let tmp = node;    // borrowck hack
                let (insert, neighbor) = if key_slice.bit(diff)
                                              { (&mut tmp.child_r, &mut tmp.child_l) }
                                         else { (&mut tmp.child_l, &mut tmp.child_r) };
                *insert = Some(Box::new(PatriciaTree {
                    data: None,
                    child_l: None,
                    child_r: None,
                    skip_prefix: key.bit_slice(idx + diff + 1, key_len),
                    skip_len: (key_len - idx - diff - 1) as u8
                }));
                *neighbor = Some(Box::new(PatriciaTree {
                    data: value_neighbor,
                    child_l: child_l,
                    child_r: child_r,
                    skip_prefix: tmp.skip_prefix >> (diff + 1),
                    skip_len: tmp.skip_len - diff as u8 - 1
                }));
                // Chop the prefix down
                tmp.skip_len = diff as u8;
                tmp.skip_prefix = tmp.skip_prefix.mask(diff);
                // Recurse
                idx += 1 + diff;
                node = &mut **insert.as_mut().unwrap();
            }
            // Prefixes match
            else {
                let slice_len = key_len - idx;
                // Search key is shorter than skip prefix: truncate the prefix and attach
                // the old data as a child
                if node.skip_len as usize > slice_len {
                    // Remove the old node's children
                    let child_l = node.child_l.take();
                    let child_r = node.child_r.take();
                    let value_neighbor = node.data.take();
                    // Put the old data in a new child, with the remainder of the prefix
                    let new_child = if node.skip_prefix.bit(slice_len)
                                         { &mut node.child_r } else { &mut node.child_l };
                    *new_child = Some(Box::new(PatriciaTree {
                        data: value_neighbor,
                        child_l: child_l,
                        child_r: child_r,
                        skip_prefix: node.skip_prefix >> (slice_len + 1),
                        skip_len: node.skip_len - slice_len as u8 - 1
                    }));
                    // Chop the prefix down and put the new data in place
                    node.skip_len = slice_len as u8;
                    node.skip_prefix = key_slice;
                    node.data = Some(value);
                    return true;
                }
                // If we have an exact match, great, insert it
                else if node.skip_len as usize == slice_len {
                    if node.data.is_none() {
                        node.data = Some(value);
                        return true;
                    }
                    if overwrite {
                        node.data = Some(value);
                    }
                    return false;
                }
                // Search key longer than node key, recurse
                else {
                    let tmp = node;    // hack to appease borrowck
                    idx += tmp.skip_len as usize + 1;
                    let subtree = if key.bit(idx - 1)
                                      { &mut tmp.child_r } else { &mut tmp.child_l };
                    // Recurse, adding a new node if necessary
                    if subtree.is_none() {
                        *subtree = Some(Box::new(PatriciaTree {
                            data: None,
                            child_l: None,
                            child_r: None,
                            skip_prefix: key.bit_slice(idx, key_len),
                            skip_len: (key_len - idx) as u8
                        }));
                    }
                    // subtree.get_mut_ref is a &mut Box<U> here, so &mut ** gets a &mut U
                    node = &mut **subtree.as_mut().unwrap();
                } // end search_len vs prefix len
            } // end if prefixes match
        } // end loop
    }

    /// Deletes a value with key `key`, returning it on success. If no value with
    /// the given key is found, return None
    pub fn delete(&mut self, key: &K, key_len: usize) -> Option<V> {
        /// Return value is (deletable, actual return value), where `deletable` is true
        /// is true when the entire node can be deleted (i.e. it has no children)
        fn recurse<K, V>(tree: &mut PatriciaTree<K, V>, key: &K, key_len: usize) -> (bool, Option<V>)
            where K: Copy + BitArray + cmp::Eq + Zero + One +
                     ops::Add<K, Output=K> +
                     ops::Shr<usize, Output=K> +
                     ops::Shl<usize, Output=K>
        {
            // If the search key is shorter than the node prefix, there is no
            // way we can match, so fail.
            if key_len < tree.skip_len as usize {
                return (false, None);
            }

            // Key fails to match prefix --- no match
            if tree.skip_prefix != key.mask(tree.skip_len as usize) {
                return (false, None);
            }

            // If we are here, the key matches the prefix
            if tree.skip_len as usize == key_len {
                // Exact match -- delete and return
                let ret = tree.data.take();
                let bit = tree.child_r.is_some();
                // First try to consolidate if there is only one child
                if tree.child_l.is_some() && tree.child_r.is_some() {
                    // Two children means we cannot consolidate or delete
                    return (false, ret);
                }
                match (tree.child_l.take(), tree.child_r.take()) {
                    (Some(_), Some(_)) => unreachable!(),
                    (Some(child), None) | (None, Some(child)) => {
                        let child = *child;  /* workaround for rustc #28536 */
                        let PatriciaTree { data, child_l, child_r, skip_len, skip_prefix } = child;
                        tree.data = data;
                        tree.child_l = child_l;
                        tree.child_r = child_r;
                        let new_bit = if bit { let ret: K = One::one();
                                               ret << (tree.skip_len as usize) }
                                      else   { Zero::zero() };
                        tree.skip_prefix = tree.skip_prefix + 
                                           new_bit +
                                           (skip_prefix << (1 + tree.skip_len as usize));
                        tree.skip_len += 1 + skip_len;
                        return (false, ret);
                    }
                    // No children means this node is deletable
                    (None, None) => { return (true, ret); }
                }
            }

            // Otherwise, the key is longer than the prefix and we need to recurse
            let next_bit = key.bit(tree.skip_len as usize);
            // Recursively get the return value. This awkward scope is required
            // to shorten the time we mutably borrow the node's children -- we
            // might want to borrow the sibling later, so the borrow needs to end.
            let ret = {
                let target = if next_bit { &mut tree.child_r } else { &mut tree.child_l };

                // If we can't recurse, fail
                if target.is_none() {
                    return (false, None);
                }
                // Otherwise, do it
                let (delete_child, ret) = recurse(&mut **target.as_mut().unwrap(),
                                                  &(*key >> (tree.skip_len as usize + 1)),
                                                  key_len - tree.skip_len as usize - 1);
                if delete_child {
                    target.take();
                }
                ret
            };

            // The above block may have deleted the target. If we now have only one
            // child, merge it into the parent. (If we have no children, mark this
            // node for deletion.)
            if tree.data.is_some() {
                // First though, if this is a data node, we can neither delete nor
                // consolidate it.
                return (false, ret);
            }

            match (tree.child_r.is_some(), tree.child_l.take(), tree.child_r.take()) {
                // Two children? Can't do anything, just sheepishly put them back
                (_, Some(child_l), Some(child_r)) => {
                    tree.child_l = Some(child_l);
                    tree.child_r = Some(child_r);
                    (false, ret)
                }
                // One child? Consolidate
                (bit, Some(child), None) | (bit, None, Some(child)) => {
                    let child = *child;  /* workaround for rustc #28536 */
                    let PatriciaTree { data, child_l, child_r, skip_len, skip_prefix } = child;
                    tree.data = data;
                    tree.child_l = child_l;
                    tree.child_r = child_r;
                    let new_bit = if bit { let ret: K = One::one();
                                           ret << (tree.skip_len as usize) }
                                  else { Zero::zero() };
                    tree.skip_prefix = tree.skip_prefix + 
                                       new_bit +
                                       (skip_prefix << (1 + tree.skip_len as usize));
                    tree.skip_len += 1 + skip_len;
                    (false, ret)
                }
                // No children? Delete
                (_, None, None) => {
                    (true, ret)
                }
            }
        }
        let (_, ret) = recurse(self, key, key_len);
        ret
    }

    /// Count all the nodes
    pub fn node_count(&self) -> usize {
        fn recurse<K: Copy, V>(node: &Option<Box<PatriciaTree<K, V>>>) -> usize {
            match *node {
                Some(ref node) => { 1 + recurse(&node.child_l) + recurse(&node.child_r) }
                None => 0
            }
        }
        1 + recurse(&self.child_l) + recurse(&self.child_r)
    }

    /// Returns an iterator over all elements in the tree
    pub fn iter(&self) -> Items<K, V> {
        Items {
            node: Some(self),
            parents: vec![],
            started: false
        }
    }

    /// Returns a mutable iterator over all elements in the tree
    pub fn mut_iter(&mut self) -> MutItems<K, V> {
        MutItems {
            node: self as *mut _,
            parents: vec![],
            started: false,
            marker: marker::PhantomData
        }
    }
}

impl<K: Copy + BitArray, V: Debug> Debug for PatriciaTree<K, V> {
    /// Print the entire tree
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fn recurse<K, V>(tree: &PatriciaTree<K, V>, f: &mut fmt::Formatter, depth: usize) -> Result<(), fmt::Error>
            where K: Copy + BitArray, V: Debug
        {
            for i in 0..tree.skip_len as usize {
                try!(write!(f, "{:}", if tree.skip_prefix.bit(i) { 1 } else { 0 }));
            }
            try!(writeln!(f, ": {:?}", tree.data));
            // left gets no indentation
            if let Some(ref t) = tree.child_l {
                for _ in 0..(depth + tree.skip_len as usize) {
                    try!(write!(f, "-"));
                }
                try!(write!(f, "0"));
                try!(recurse(&**t, f, depth + tree.skip_len as usize + 1));
            }
            // right one gets indentation
            if let Some(ref t) = tree.child_r {
                for _ in 0..(depth + tree.skip_len as usize) {
                    try!(write!(f, "_"));
                }
                try!(write!(f, "1"));
                try!(recurse(&**t, f, depth + tree.skip_len as usize + 1));
            }
            Ok(())
        }
        recurse(self, f, 0)
    }
}

impl<S, K, V> ConsensusEncodable<S> for PatriciaTree<K, V>
    where S: SimpleEncoder,
          K: Copy + ConsensusEncodable<S>,
          V: ConsensusEncodable<S>
{
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        // Depth-first serialization: serialize self, then children
        try!(self.skip_prefix.consensus_encode(s));
        try!(self.skip_len.consensus_encode(s));
        try!(self.data.consensus_encode(s));
        try!(self.child_l.consensus_encode(s));
        try!(self.child_r.consensus_encode(s));
        Ok(())
    }
}

impl<D, K, V> ConsensusDecodable<D> for PatriciaTree<K, V>
    where D: SimpleDecoder,
          K: Copy + ConsensusDecodable<D>,
          V: ConsensusDecodable<D>
{
    fn consensus_decode(d: &mut D) -> Result<PatriciaTree<K, V>, D::Error> {
        Ok(PatriciaTree {
            skip_prefix: try!(ConsensusDecodable::consensus_decode(d)),
            skip_len: try!(ConsensusDecodable::consensus_decode(d)),
            data: try!(ConsensusDecodable::consensus_decode(d)),
            child_l: try!(ConsensusDecodable::consensus_decode(d)),
            child_r: try!(ConsensusDecodable::consensus_decode(d))
        })
    }
}

/// Iterator
pub struct Items<'tree, K: Copy + 'tree, V: 'tree> {
    started: bool,
    node: Option<&'tree PatriciaTree<K, V>>,
    parents: Vec<&'tree PatriciaTree<K, V>>
}

/// Mutable iterator
pub struct MutItems<'tree, K: Copy + 'tree, V: 'tree> {
    started: bool,
    node: *mut PatriciaTree<K, V>,
    parents: Vec<*mut PatriciaTree<K, V>>,
    marker: marker::PhantomData<&'tree PatriciaTree<K, V>>
}

impl<'a, K: Copy, V> Iterator for Items<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        fn borrow_opt<K: Copy, V>(opt_ptr: &Option<Box<PatriciaTree<K, V>>>) -> Option<&PatriciaTree<K, V>> {
            opt_ptr.as_ref().map(|b| &**b)
        }

        // If we haven't started, maybe return the "last" return value,
        // which will be the root node.
        if !self.started {
            if self.node.is_some() && (**self.node.as_ref().unwrap()).data.is_some() {
                return self.node.unwrap().data.as_ref();
            }
            self.started = true;
        }

        // Find next data-containing node
        while self.node.is_some() {
            let mut node = self.node.take();
            // Try to go left
            let child_l = borrow_opt(&node.unwrap().child_l);
            if child_l.is_some() {
                self.parents.push(node.unwrap());
                self.node = child_l;
            // Try to go right, going back up the tree if necessary
            } else {
                while node.is_some() {
                    let child_r = borrow_opt(&node.unwrap().child_r);
                    if child_r.is_some() {
                        self.node = child_r;
                        break;
                    }
                    node = self.parents.pop();
                }
            }
            // Stop if we've found data.
            if self.node.is_some() && self.node.unwrap().data.is_some() {
                break;
            }
        } // end loop
        // Return data
        self.node.and_then(|node| node.data.as_ref())
    }
}

impl<'a, K: Copy, V> Iterator for MutItems<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<&'a mut V> {
        fn borrow_opt<K: Copy, V>(opt_ptr: &Option<Box<PatriciaTree<K, V>>>) -> *mut PatriciaTree<K, V> {
            match *opt_ptr {
                Some(ref data) => &**data as *const _ as *mut _,
                None => ptr::null_mut()
            }
        }

        // If we haven't started, maybe return the "last" return value,
        // which will be the root node.
        if !self.started {
            unsafe {
                if !self.node.is_null() && (*self.node).data.is_some() {
                    return (*self.node).data.as_mut();
                }
            }
            self.started = true;
        }

        // Find next data-containing node
        while !self.node.is_null() {
            // Try to go left
            let child_l = unsafe { borrow_opt(&(*self.node).child_l) };
            if !child_l.is_null() {
                self.parents.push(self.node);
                self.node = child_l;
            // Try to go right, going back up the tree if necessary
            } else {
                while !self.node.is_null() {
                    let child_r = unsafe { borrow_opt(&(*self.node).child_r) };
                    if !child_r.is_null() {
                        self.node = child_r;
                        break;
                    }
                    self.node = self.parents.pop().unwrap_or(ptr::null_mut());
                }
            }
            // Stop if we've found data.
            if !self.node.is_null() && unsafe { (*self.node).data.is_some() } {
                break;
            }
        } // end loop
        // Return data
        if !self.node.is_null() {
            unsafe { (*self.node).data.as_mut() }
        } else { 
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use num::Zero;
    use num::FromPrimitive;

    use network::serialize::{deserialize, serialize};
    use util::hash::Sha256dHash;
    use util::uint::Uint128;
    use util::uint::Uint256;
    use util::patricia_tree::PatriciaTree;

    #[test]
    fn patricia_single_insert_lookup_delete_test() {
        let mut key: Uint256 = FromPrimitive::from_u64(0xDEADBEEFDEADBEEF).unwrap();
        key = key + (key << 64);

        let mut tree = PatriciaTree::new();
        tree.insert(&key, 100, 100u32);
        tree.insert(&key, 120, 100u32);

        assert_eq!(tree.lookup(&key, 100), Some(&100u32));
        assert_eq!(tree.lookup(&key, 101), None);
        assert_eq!(tree.lookup(&key, 99), None);
        assert_eq!(tree.delete(&key, 100), Some(100u32));
    }

    #[test]
    fn patricia_insert_lookup_delete_test() {
        let mut tree = PatriciaTree::new();
        let mut hashes = vec![];
        for i in 0u32..5000 {
            let hash = Sha256dHash::from_data(&[(i / 0x100) as u8, (i % 0x100) as u8]).into_le().low_128();
            tree.insert(&hash, 250, i);
            hashes.push(hash);
        }

        // Check that all inserts are correct
        for (n, hash) in hashes.iter().enumerate() {
            let ii = n as u32;
            let ret = tree.lookup(hash, 250);
            assert_eq!(ret, Some(&ii));
        }

        // Delete all the odd-numbered nodes
        for (n, hash) in hashes.iter().enumerate() {
            if n % 2 == 1 {
                let ii = n as u32;
                let ret = tree.delete(hash, 250);
                assert_eq!(ret, Some(ii));
            }
        }

        // Confirm all is correct
        for (n, hash) in hashes.iter().enumerate() {
            let ii = n as u32;
            let ret = tree.lookup(hash, 250);
            if n % 2 == 0 {
                assert_eq!(ret, Some(&ii));
            } else {
                assert_eq!(ret, None);
            }
        }
    }

    #[test]
    fn patricia_insert_substring_keys() {
        // This test uses a bunch of keys that are substrings of each other
        // to make sure insertion and deletion does not lose data
        let mut tree = PatriciaTree::new();
        let mut hashes = vec![];
        // Start by inserting a bunch of chunder
        for i in 1u32..500 {
            let hash = Sha256dHash::from_data(&[(i / 0x100) as u8, (i % 0x100) as u8]).into_le().low_128();
            tree.insert(&hash, 128, i * 1000);
            hashes.push(hash);
        }
        // Do the actual test -- note that we also test insertion and deletion
        // at the root here.
        for i in 0u32..10 {
            tree.insert(&Zero::zero(), i as usize, i);
        }
        for i in 0u32..10 {
            let m = tree.lookup(&Zero::zero(), i as usize);
            assert_eq!(m, Some(&i));
        }
        for i in 0u32..10 {
            let m = tree.delete(&Zero::zero(), i as usize);
            assert_eq!(m, Some(i));
        }
        // Check that the chunder was unharmed
        for (n, hash) in hashes.iter().enumerate() {
            let ii = ((n + 1) * 1000) as u32;
            let ret = tree.lookup(hash, 128);
            assert_eq!(ret, Some(&ii));
        }
    }

    #[test]
    fn patricia_iter_test() {
        let n_elems = 5000;
        let mut tree = PatriciaTree::new();
        let mut data = vec![None; n_elems];
        // Start by inserting a bunch of stuff
        for i in 0..n_elems {
            let hash = Sha256dHash::from_data(&[(i / 0x100) as u8, (i % 0x100) as u8]).into_le().low_128();
            tree.insert(&hash, 128, i);
            data[i] = Some(());
        }

        // Iterate over and try to get everything
        for n in tree.iter() {
            assert!(data[*n].is_some());
            data[*n] = None;
        }

        // Check that we got everything
        assert!(data.iter().all(|opt| opt.is_none()));
    }

    #[test]
    fn patricia_mut_iter_test() {
        let n_elems = 5000;
        let mut tree = PatriciaTree::new();
        let mut data = vec![None; n_elems];
        // Start by inserting a bunch of stuff
        for i in 0..n_elems {
            let hash = Sha256dHash::from_data(&[(i / 0x100) as u8, (i % 0x100) as u8]).into_le().low_128();
            tree.insert(&hash, 128, i);
            data[i] = Some(());
        }

        // Iterate over and flip all the values
        for n in tree.mut_iter() {
            *n = n_elems - *n - 1;
        }

        // Iterate over and try to get everything
        for n in tree.mut_iter() {
            assert!(data[*n].is_some());
            data[*n] = None;
        }

        // Check that we got everything
        assert!(data.iter().all(|opt| opt.is_none()));
    }

    #[test]
    fn patricia_serialize_test() {
        // Build a tree
        let mut tree = PatriciaTree::new();
        let mut hashes = vec![];
        for i in 0u32..5000 {
            let hash = Sha256dHash::from_data(&[(i / 0x100) as u8, (i % 0x100) as u8]).into_le().low_128();
            tree.insert(&hash, 250, i);
            hashes.push(hash);
        }

        // Serialize it
        let serialized = serialize(&tree).unwrap();
        // Deserialize it
        let deserialized: Result<PatriciaTree<Uint128, u32>, _> = deserialize(&serialized);
        assert!(deserialized.is_ok());
        let new_tree = deserialized.unwrap();

        // Check that all inserts are still there
        for (n, hash) in hashes.iter().enumerate() {
            let ii = n as u32;
            let ret = new_tree.lookup(hash, 250);
            assert_eq!(ret, Some(&ii));
        }
    }
}

