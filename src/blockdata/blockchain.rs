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

//! # Bitcoin Blockchain
//!
//! This module provides the structures and functions to maintain the
//! blockchain.
//!

use num::{FromPrimitive, Zero};
use std::{marker, ptr};

use blockdata::block::{Block, BlockHeader};
use blockdata::transaction::Transaction;
use blockdata::constants::{DIFFCHANGE_INTERVAL, DIFFCHANGE_TIMESPAN,
                                                     TARGET_BLOCK_SPACING, max_target, genesis_block};
use network::constants::Network;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{BitcoinHash, SimpleDecoder, SimpleEncoder};
use util::BitArray;
use util;
use util::Error::{BlockNotFound, DuplicateHash, PrevHashNotFound};
use util::uint::Uint256;
use util::hash::Sha256dHash;
use util::patricia_tree::PatriciaTree;

type BlockTree = PatriciaTree<Uint256, Box<BlockchainNode>>;
type NodePtr = *const BlockchainNode;

/// A link in the blockchain
pub struct BlockchainNode {
    /// The actual block
    pub block: Block,
    /// Total work from genesis to this point
    pub total_work: Uint256,
    /// Expected value of `block.header.bits` for this block; only changes every
    /// `blockdata::constants::DIFFCHANGE_INTERVAL;` blocks
    pub required_difficulty: Uint256,
    /// Height above genesis
    pub height: u32,
    /// Whether the transaction data is stored
    pub has_txdata: bool,
    /// Pointer to block's parent
    prev: NodePtr,
    /// Pointer to block's child
    next: NodePtr
}

impl BlockchainNode {
    /// Is the node on the main chain?
    fn is_on_main_chain(&self, chain: &Blockchain) -> bool {
        if self.block.header == unsafe { (*chain.best_tip).block.header } {
            true
        } else {
            unsafe {
                let mut scan = self.next;
                while !scan.is_null() {
                    if (*scan).block.header == (*chain.best_tip).block.header {
                        return true;
                    }
                    scan = (*scan).next;
                }
            }
            false
        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for BlockchainNode {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        try!(self.block.consensus_encode(s));
        try!(self.total_work.consensus_encode(s));
        try!(self.required_difficulty.consensus_encode(s));
        try!(self.height.consensus_encode(s));
        try!(self.has_txdata.consensus_encode(s));
        // Don't serialize the prev or next pointers
        Ok(())
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for BlockchainNode {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<BlockchainNode, D::Error> {
        Ok(BlockchainNode {
            block: try!(ConsensusDecodable::consensus_decode(d)),
            total_work: try!(ConsensusDecodable::consensus_decode(d)),
            required_difficulty: try!(ConsensusDecodable::consensus_decode(d)),
            height: try!(ConsensusDecodable::consensus_decode(d)),
            has_txdata: try!(ConsensusDecodable::consensus_decode(d)),
            prev: ptr::null(),
            next: ptr::null()
        })
    }
}

impl BitcoinHash for BlockchainNode {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.block.header.bitcoin_hash()
    }
}

/// The blockchain
pub struct Blockchain {
    network: Network,
    tree: BlockTree,
    best_tip: NodePtr,
    best_hash: Sha256dHash,
    genesis_hash: Sha256dHash
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Blockchain {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        try!(self.network.consensus_encode(s));
        try!(self.tree.consensus_encode(s));
        try!(self.best_hash.consensus_encode(s));
        try!(self.genesis_hash.consensus_encode(s));
        Ok(())
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Blockchain {
    fn consensus_decode(d: &mut D) -> Result<Blockchain, D::Error> {
        let network: Network = try!(ConsensusDecodable::consensus_decode(d));
        let mut tree: BlockTree = try!(ConsensusDecodable::consensus_decode(d));
        let best_hash: Sha256dHash = try!(ConsensusDecodable::consensus_decode(d));
        let genesis_hash: Sha256dHash = try!(ConsensusDecodable::consensus_decode(d));

        // Lookup best tip
        let best = match tree.lookup(&best_hash.into_le(), 256) {
            Some(node) => &**node as NodePtr,
            None => {
                return Err(d.error(format!("best tip {:x} not in tree", best_hash)));
            }
        };
        // Lookup genesis
        if tree.lookup(&genesis_hash.into_le(), 256).is_none() {
            return Err(d.error(format!("genesis {:x} not in tree", genesis_hash)));
        }
        // Reconnect all prev pointers
        let raw_tree = &tree as *const BlockTree;
        for node in tree.mut_iter() {
            let hash = node.block.header.prev_blockhash.into_le();
            let prevptr =
                match unsafe { (*raw_tree).lookup(&hash, 256) } {
                    Some(node) => &**node as NodePtr,
                    None => ptr::null() 
                };
            node.prev = prevptr;
        }
        // Reconnect next pointers on the main chain
        unsafe {
            let mut scan = best;
            while !(*scan).prev.is_null() {
                let prev = (*scan).prev as *mut BlockchainNode;
                (*prev).next = scan;
                scan = prev as NodePtr;
            }

            // Check that "genesis" is the genesis
            if (*scan).bitcoin_hash() != genesis_hash {
                return Err(d.error(format!("no path from tip {:x} to genesis {:x}",
                                                                     best_hash, genesis_hash)));
            }
        }

        // Return the chain
        Ok(Blockchain {
            network: network,
            tree: tree,
            best_tip: best,
            best_hash: best_hash,
            genesis_hash: genesis_hash
        })
    }
}

// TODO: this should maybe be public, in which case it needs to be tagged
// with a PhantomData marker tying it to the tree's lifetime.
struct LocatorHashIter {
    index: NodePtr,
    count: usize,
    skip: usize
}

impl LocatorHashIter {
    fn new(init: NodePtr) -> LocatorHashIter {
        LocatorHashIter { index: init, count: 0, skip: 1 }
    }
}

impl Iterator for LocatorHashIter {
    type Item = Sha256dHash;

    fn next(&mut self) -> Option<Sha256dHash> {
        if self.index.is_null() {
            return None;
        }
        let ret = Some(unsafe { (*self.index).bitcoin_hash() });

        // Rewind once (if we are at the genesis, this will set self.index to None)
        self.index = unsafe { (*self.index).prev };
        // If we are not at the genesis, rewind `self.skip` times, or until we are.
        if !self.index.is_null() {
            for _ in 1..self.skip {
                unsafe {
                    if (*self.index).prev.is_null() {
                        break;
                    }
                    self.index = (*self.index).prev;
                }
            }
        }

        self.count += 1;
        if self.count > 10 {
            self.skip *= 2;
        }
        ret
    }
}

/// An iterator over blocks in blockheight order
pub struct BlockIter<'tree> {
    index: NodePtr,
    // Note: we don't actually touch the blockchain. But we need
    // to keep it borrowed to prevent it being mutated, since some
    // mutable blockchain methods call .mut_borrow() on the block
    // links, which would blow up if the iterator did a regular
    // borrow at the same time.
    marker: marker::PhantomData<&'tree Blockchain>
}

/// An iterator over blocks in reverse blockheight order. Note that this
/// is essentially the same as if we'd implemented `DoubleEndedIterator`
/// on `BlockIter` --- but we can't do that since if `BlockIter` is started
/// off the main chain, it will not reach the best tip, so the iterator
/// and its `.rev()` would be iterators over different chains! To avoid
/// this suprising behaviour we simply use separate iterators.
pub struct RevBlockIter<'tree> {
    index: NodePtr,
    // See comment in BlockIter for why we need this
    marker: marker::PhantomData<&'tree Blockchain>
}

/// An iterator over blocks in reverse blockheight order, which yielding only
/// stale blocks (ending at the point where it would've returned a block on
/// the main chain). It does this by checking if the `next` pointer of the
/// next-to-by-yielded block matches the currently-yielded block. If not, scan
/// forward from next-to-be-yielded block. If we hit the best tip, set the
/// next-to-by-yielded block to None instead.
///
/// So to handle reorgs, you create a `RevStaleBlockIter` starting from the last
/// known block, and play it until it runs out, rewinding every block except for
/// the last one. Since the `UtxoSet` `rewind` function sets its `last_hash()` to
/// the prevblockhash of the rewinded block (which will be on the main chain at
/// the end of the iteration), you can then sync it up same as if you were doing
/// a plain old fast-forward.
pub struct RevStaleBlockIter<'tree> {
    index: NodePtr,
    chain: &'tree Blockchain
}

impl<'tree> Iterator for BlockIter<'tree> {
    type Item = &'tree BlockchainNode;

    fn next(&mut self) -> Option<&'tree BlockchainNode> {
        if self.index.is_null() {
            return None;
        }
        unsafe {
            let ret = Some(&*self.index);
            self.index = (*self.index).next;
            ret
        }
    }
}

impl<'tree> Iterator for RevBlockIter<'tree> {
    type Item = &'tree BlockchainNode;

    fn next(&mut self) -> Option<&'tree BlockchainNode> {
        if self.index.is_null() {
            return None;
        }
        unsafe {
            let ret = Some(&*self.index);
            self.index = (*self.index).prev;
            ret
        }
    }
}

impl<'tree> Iterator for RevStaleBlockIter<'tree> {
    type Item = &'tree Block;

    fn next(&mut self) -> Option<&'tree Block> { 
        if self.index.is_null() {
            return None;
        }

        unsafe {
            let ret = Some(&(*self.index).block);
            let next_index = (*self.index).prev;
            // Check if the next block is going to be on the main chain
            if !next_index.is_null() &&
                 (*next_index).next != self.index &&
                 (&*next_index).is_on_main_chain(self.chain) {
                self.index = ptr::null();
            } else {
                self.index = next_index;
            }
            ret
        }
    }
}

/// This function emulates the `GetCompact(SetCompact(n))` in the satoshi code,
/// which drops the precision to something that can be encoded precisely in
/// the nBits block header field. Savour the perversity. This is in Bitcoin
/// consensus code. What. Gaah!
fn satoshi_the_precision(n: Uint256) -> Uint256 {
    // Shift by B bits right then left to turn the low bits to zero
    let bits = 8 * ((n.bits() + 7) / 8 - 3);
    let mut ret = n >> bits;
    // Oh, did I say B was that fucked up formula? I meant sometimes also + 8.
    if ret.bit(23) {
        ret = (ret >> 8) << 8;
    }
    ret << bits
}

impl Blockchain {
    /// Constructs a new blockchain
    pub fn new(network: Network) -> Blockchain {
        let genesis = genesis_block(network);
        let genhash = genesis.header.bitcoin_hash();
        let new_node = Box::new(BlockchainNode {
            total_work: Zero::zero(),
            required_difficulty: genesis.header.target(),
            block: genesis,
            height: 0,
            has_txdata: true,
            prev: ptr::null(),
            next: ptr::null()
        });
        let raw_ptr = &*new_node as NodePtr;
        Blockchain {
            network: network,
            tree: {
                let mut pat = PatriciaTree::new();
                pat.insert(&genhash.into_le(), 256, new_node);
                pat
            },
            best_hash: genhash,
            genesis_hash: genhash,
            best_tip: raw_ptr
        }
    }

    fn replace_txdata(&mut self, hash: &Uint256, txdata: Vec<Transaction>, has_txdata: bool) -> Result<(), util::Error> {
        match self.tree.lookup_mut(hash, 256) {
            Some(mut existing_block) => {
                existing_block.block.txdata.clone_from(&txdata);
                existing_block.has_txdata = has_txdata;
                Ok(())
            },
            None => Err(BlockNotFound)
        }
    }

    /// Looks up a block in the chain and returns the BlockchainNode containing it
    pub fn get_block(&self, hash: Sha256dHash) -> Option<&BlockchainNode> {
        self.tree.lookup(&hash.into_le(), 256).map(|node| &**node)
    }

    /// Locates a block in the chain and overwrites its txdata
    pub fn add_txdata(&mut self, block: Block) -> Result<(), util::Error> {
        self.replace_txdata(&block.header.bitcoin_hash().into_le(), block.txdata, true)
    }

    /// Locates a block in the chain and removes its txdata
    pub fn remove_txdata(&mut self, hash: Sha256dHash) -> Result<(), util::Error> {
        self.replace_txdata(&hash.into_le(), vec![], false)
    }

    /// Adds a block header to the chain
    pub fn add_header(&mut self, header: BlockHeader) -> Result<(), util::Error> {
        self.real_add_block(Block { header: header, txdata: vec![] }, false)
    }

    /// Adds a block to the chain
    pub fn add_block(&mut self, block: Block) -> Result<(), util::Error> {
        self.real_add_block(block, true)
    }

    fn real_add_block(&mut self, block: Block, has_txdata: bool) -> Result<(), util::Error> {
        // get_prev optimizes the common case where we are extending the best tip
        #[inline]
        fn get_prev(chain: &Blockchain, hash: Sha256dHash) -> Option<NodePtr> {
            if hash == chain.best_hash { 
                Some(chain.best_tip)
            } else {
                chain.tree.lookup(&hash.into_le(), 256).map(|boxptr| &**boxptr as NodePtr)
            }
        }
        // Check for multiple inserts (bitcoind from c9a09183 to 3c85d2ec doesn't
        // handle locator hashes properly and may return blocks multiple times,
        // and this may also happen in case of a reorg.
        if self.tree.lookup(&block.header.bitcoin_hash().into_le(), 256).is_some() {
            return Err(DuplicateHash);
        }
        // Construct node, if possible
        let new_block = match get_prev(self, block.header.prev_blockhash) {
            Some(prev) => {
                let difficulty =
                    // Compute required difficulty if this is a diffchange block
                    if (unsafe { (*prev).height } + 1) % DIFFCHANGE_INTERVAL == 0 {
                        let timespan = unsafe {
                            // Scan back DIFFCHANGE_INTERVAL blocks
                            let mut scan = prev;
                            for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                                scan = (*scan).prev;
                            }
                            // Get clamped timespan between first and last blocks
                            match (*prev).block.header.time - (*scan).block.header.time {
                                n if n < DIFFCHANGE_TIMESPAN / 4 => DIFFCHANGE_TIMESPAN / 4,
                                n if n > DIFFCHANGE_TIMESPAN * 4 => DIFFCHANGE_TIMESPAN * 4,
                                n => n
                            }
                        };
                        // Compute new target
                        let mut target = unsafe { (*prev).block.header.target() };
                        target = target.mul_u32(timespan);
                        target = target / FromPrimitive::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
                        // Clamp below MAX_TARGET (difficulty 1)
                        let max = max_target(self.network);
                        if target > max { target = max };
                        // Compactify (make expressible in the 8+24 nBits float format
                        satoshi_the_precision(target)
                    // On non-diffchange blocks, Testnet has a rule that any 20-minute-long
                    // block intervals result the difficulty
                    } else if self.network == Network::Testnet &&
                                        block.header.time > unsafe { (*prev).block.header.time } + 2*TARGET_BLOCK_SPACING {
                        max_target(self.network)
                    // On the other hand, if we are in Testnet and the block interval is less
                    // than 20 minutes, we need to scan backward to find a block for which the
                    // previous rule did not apply, to find the "real" difficulty.
                    } else if self.network == Network::Testnet {
                        // Scan back DIFFCHANGE_INTERVAL blocks
                        unsafe {
                            let mut scan = prev;
                            while (*scan).height % DIFFCHANGE_INTERVAL != 0 &&
                                        (*scan).required_difficulty == max_target(self.network) {
                                scan = (*scan).prev;
                            }
                            (*scan).required_difficulty
                        }
                    // Otherwise just use the last block's difficulty
                    } else {
                        unsafe { (*prev).required_difficulty }
                    };
                // Create node
                let ret = Box::new(BlockchainNode {
                    total_work: block.header.work() + unsafe { (*prev).total_work },
                    block: block,
                    required_difficulty: difficulty,
                    height: unsafe { (*prev).height + 1 },
                    has_txdata: has_txdata,
                    prev: prev,
                    next: ptr::null()
                });
                unsafe {
                    let prev = prev as *mut BlockchainNode;
                    (*prev).next = &*ret as NodePtr;
                }
                ret
            },
            None => {
                return Err(PrevHashNotFound);
            }
        };

        // spv validate the block
        try!(new_block.block.header.spv_validate(&new_block.required_difficulty));

        // Insert the new block
        let raw_ptr = &*new_block as NodePtr;
        self.tree.insert(&new_block.block.header.bitcoin_hash().into_le(), 256, new_block);
        // Replace the best tip if necessary
        if unsafe { (*raw_ptr).total_work > (*self.best_tip).total_work } {
            self.set_best_tip(raw_ptr);
        }
        Ok(())
    }

    /// Sets the best tip (not public)
    fn set_best_tip(&mut self, tip: NodePtr) {
        // Fix next links
        unsafe {
            let mut scan = self.best_tip;
            // Scan backward
            while !(*scan).prev.is_null() {
                // If we hit the old best, there is no need to reorg.
                if scan == self.best_tip { break; }
                // Otherwise set the next-ptr and carry on
                let prev = (*scan).prev as *mut BlockchainNode;
                (*prev).next = scan;
                scan = (*scan).prev;
            }
        }
        // Set best
        self.best_hash = unsafe { (*tip).bitcoin_hash() };
        self.best_tip = tip;
    }

    /// Returns the genesis block's blockhash
    pub fn genesis_hash(&self) -> Sha256dHash {
        self.genesis_hash
    }

    /// Returns the best tip
    pub fn best_tip(&self) -> &Block {
        unsafe { &(*self.best_tip).block }
    }

    /// Returns the best tip's blockhash
    pub fn best_tip_hash(&self) -> Sha256dHash {
        self.best_hash
    }

    /// Returns an array of locator hashes used in `getheaders` messages
    pub fn locator_hashes(&self) -> Vec<Sha256dHash> {
        LocatorHashIter::new(self.best_tip).collect()
    }

    /// An iterator over all blocks in the chain starting from `start_hash`
    pub fn iter(&self, start_hash: Sha256dHash) -> BlockIter {
        let start = match self.tree.lookup(&start_hash.into_le(), 256) {
                Some(boxptr) => &**boxptr as NodePtr,
                None => ptr::null()
            };
        BlockIter {
            index: start,
            marker: marker::PhantomData
        }
    }

    /// An iterator over all blocks in reverse order to the genesis, starting with `start_hash`
    pub fn rev_iter(&self, start_hash: Sha256dHash) -> RevBlockIter {
        let start = match self.tree.lookup(&start_hash.into_le(), 256) {
                Some(boxptr) => &**boxptr as NodePtr,
                None => ptr::null()
            };
        RevBlockIter {
            index: start,
            marker: marker::PhantomData
        }
    }

    /// An iterator over all blocks -not- in the best chain, in reverse order, starting from `start_hash`
    pub fn rev_stale_iter(&self, start_hash: Sha256dHash) -> RevStaleBlockIter {
        let start = match self.tree.lookup(&start_hash.into_le(), 256) {
                Some(boxptr) => {
                    // If we are already on the main chain, we have a dead iterator
                    if boxptr.is_on_main_chain(self) {
                        ptr::null()
                    } else {
                        &**boxptr as NodePtr
                    }
                }
                None => ptr::null()
            };
        RevStaleBlockIter { 
            index: start,
            chain: self
        }
    }
}

#[cfg(test)]
mod tests {
    use blockdata::blockchain::Blockchain;
    use blockdata::constants::genesis_block;
    use network::constants::Network::Bitcoin;
    use network::serialize::{BitcoinHash, deserialize, serialize};

    #[test]
    fn blockchain_serialize_test() {
        let empty_chain = Blockchain::new(Bitcoin);
        assert_eq!(empty_chain.best_tip().header.bitcoin_hash(),
                   genesis_block(Bitcoin).header.bitcoin_hash());

        let serial = serialize(&empty_chain);
        let deserial: Result<Blockchain, _> = deserialize(&serial.unwrap());

        assert!(deserial.is_ok());
        let read_chain = deserial.unwrap();
        assert_eq!(read_chain.best_tip().header.bitcoin_hash(),
                   genesis_block(Bitcoin).header.bitcoin_hash());
    }
}



