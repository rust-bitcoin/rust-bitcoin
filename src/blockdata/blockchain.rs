// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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
//! Note to developers: do not expose any ref-counted pointers in the public
//! API of this module. Internally we do unsafe mutations of them and we need
//! to make sure we are holding the only references.
//!

use alloc::rc::Rc;
use std::cell::{Ref, RefCell};
use std::io::{IoResult, IoError, OtherIoError};
use std::num::Zero;
use std::kinds::marker;

use blockdata::block::{Block, BlockHeader};
use blockdata::transaction::Transaction;
use blockdata::constants::{DIFFCHANGE_INTERVAL, DIFFCHANGE_TIMESPAN, max_target};
use network::serialize::{Serializable, SerializeIter};
use util::BitArray;
use util::uint::Uint256;
use util::hash::Sha256dHash;
use util::misc::prepend_err;
use util::patricia_tree::PatriciaTree;

type BlockTree = PatriciaTree<Rc<BlockchainNode>, Uint256>;
type NodePtr = Option<Rc<BlockchainNode>>;

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
  prev: RefCell<NodePtr>,
  /// Pointer to block's child
  next: RefCell<NodePtr>
}

impl BlockchainNode {
  /// Look up the previous link, caching the result
  fn prev(&self, tree: &BlockTree) -> NodePtr {
    let mut cache = self.prev.borrow_mut();
    if cache.is_some() {
      return Some(cache.get_ref().clone())
    }
    match tree.lookup(&self.block.header.prev_blockhash.as_uint256(), 256) {
      Some(prev) => { *cache = Some(prev.clone()); return Some(prev.clone()); }
      None => { return None; }
    }
  }

  /// Look up the next link
  fn next<'a>(&'a self) -> Ref<'a, NodePtr> {
    self.next.borrow()
  }

  /// Set the next link
  fn set_next(&self, next: Rc<BlockchainNode>) {
    let mut cache = self.next.borrow_mut();
    *cache = Some(next);
  }

  /// Is the node on the main chain?
  fn is_on_main_chain(&self, chain: &Blockchain) -> bool {
    if self.block.header == chain.best_tip.block.header {
      return true;
    }
    let mut scan = self.next().clone();
    while scan.is_some() {
      if scan.get_ref().block.header == chain.best_tip.block.header {
        return true;
      }
      scan = scan.get_ref().next().clone();
    }
    return false;
  }
}

impl Serializable for Rc<BlockchainNode> {
  fn serialize(&self) -> Vec<u8> {
    let mut ret = vec![];
    ret.extend(self.block.serialize().move_iter());
    ret.extend(self.total_work.serialize().move_iter());
    ret.extend(self.required_difficulty.serialize().move_iter());
    ret.extend(self.height.serialize().move_iter());
    ret.extend(self.has_txdata.serialize().move_iter());
    // Don't serialize the prev pointer
    ret
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Rc<BlockchainNode>> {
    Ok(Rc::new(BlockchainNode {
      block: try!(prepend_err("block", Serializable::deserialize(iter.by_ref()))),
      total_work: try!(prepend_err("total_work", Serializable::deserialize(iter.by_ref()))),
      required_difficulty: try!(prepend_err("req_difficulty", Serializable::deserialize(iter.by_ref()))),
      height: try!(prepend_err("height", Serializable::deserialize(iter.by_ref()))),
      has_txdata: try!(prepend_err("has_txdata", Serializable::deserialize(iter.by_ref()))),
      prev: RefCell::new(None),
      next: RefCell::new(None)
    }))
  }

  // Override Serialize::hash to return the blockheader hash, since the
  // hash of the node itself is pretty much meaningless.
  fn hash(&self) -> Sha256dHash {
    self.block.header.hash()
  }
}

/// The blockchain
pub struct Blockchain {
  tree: BlockTree,
  best_tip: Rc<BlockchainNode>,
  best_hash: Sha256dHash,
  genesis_hash: Sha256dHash
}

impl Serializable for Blockchain {
  fn serialize(&self) -> Vec<u8> {
    let mut ret = vec![];
    ret.extend(self.tree.serialize().move_iter());
    ret.extend(self.best_hash.serialize().move_iter());
    ret.extend(self.genesis_hash.serialize().move_iter());
    ret
  }

  fn serialize_iter<'a>(&'a self) -> SerializeIter<'a> {
    SerializeIter {
      data_iter: None,
      sub_iter_iter: box vec![ &self.tree as &Serializable,
                               &self.best_hash as &Serializable,
                               &self.genesis_hash as &Serializable ].move_iter(),
      sub_iter: None,
      sub_started: false
    }
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Blockchain> {
    let tree: BlockTree = try!(prepend_err("tree", Serializable::deserialize(iter.by_ref())));
    let best_hash: Sha256dHash = try!(prepend_err("best_hash", Serializable::deserialize(iter.by_ref())));
    let genesis_hash: Sha256dHash = try!(prepend_err("genesis_hash", Serializable::deserialize(iter.by_ref())));
    // Lookup best tip
    let best = match tree.lookup(&best_hash.as_uint256(), 256) {
      Some(rc) => rc.clone(),
      None => { return Err(IoError {
          kind: OtherIoError,
          desc: "best tip reference not found in tree",
          detail: Some(format!("best tip {:x} not found", best_hash))
        });
      }
    };
    // Lookup genesis
    if tree.lookup(&genesis_hash.as_uint256(), 256).is_none() {
      return Err(IoError {
        kind: OtherIoError,
        desc: "genesis block not found in tree",
        detail: Some(format!("genesis {:x} not found", genesis_hash))
      });
    }
    // Reconnect next and prev pointers back to "genesis", the first node
    // with no prev pointer.
    let mut scan = best.clone();
    let mut prev = best.prev(&tree);
    while prev.is_some() {
      prev.get_mut_ref().set_next(scan);
      scan = prev.get_ref().clone();
      prev = prev.get_ref().prev(&tree);
    }
    // Check that "genesis" is the genesis
    if scan.block.header.hash() != genesis_hash {
      Err(IoError {
          kind: OtherIoError,
          desc: "best tip did not link back to genesis",
          detail: Some(format!("no path from tip {:x} to genesis {:x}", best_hash, genesis_hash))
      })
    } else {
      // Return the chain
      Ok(Blockchain {
        tree: tree,
        best_tip: best.clone(),
        best_hash: best_hash,
        genesis_hash: genesis_hash
      })
    }
  }
}

struct LocatorHashIter<'tree> {
  index: NodePtr,
  tree: &'tree BlockTree,
  count: uint,
  skip: uint
}

impl<'tree> LocatorHashIter<'tree> {
  fn new<'tree>(init: Rc<BlockchainNode>, tree: &'tree BlockTree) -> LocatorHashIter<'tree> {
    LocatorHashIter { index: Some(init), tree: tree, count: 0, skip: 1 }
  }
}

impl<'tree> Iterator<Sha256dHash> for LocatorHashIter<'tree> {
  fn next(&mut self) -> Option<Sha256dHash> {
    let ret = match self.index {
      Some(ref node) => Some(node.hash()),
      None => { return None; }
    };

    // Rewind once (if we are at the genesis, this will set self.index to None)
    self.index = self.index.get_ref().prev(self.tree);
    // If we are not at the genesis, rewind `self.skip` times, or until we are.
    if self.index.is_some() {
      for _ in range(1, self.skip) {
        self.index = match self.index.get_ref().prev(self.tree) {
          Some(rc) => Some(rc),
          None => { break; }
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
  marker: marker::ContravariantLifetime<'tree>
}

/// An iterator over blocks in reverse blockheight order. Note that this
/// is essentially the same as if we'd implemented `DoubleEndedIterator`
/// on `BlockIter` --- but we can't do that since if `BlockIter` is started
/// off the main chain, it will not reach the best tip, so the iterator
/// and its `.rev()` would be iterators over different chains! To avoid
/// this suprising behaviour we simply use separate iterators.
pub struct RevBlockIter<'tree> {
  index: NodePtr,
  tree: &'tree BlockTree
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
/// the last one. Since the UtxoSet `rewind` function sets its `last_hash()` to
/// the prevblockhash of the rewinded block (which will be on the main chain at
/// the end of the iteration), you can then sync it up same as if you were doing
/// a plain old fast-forward.
pub struct RevStaleBlockIter<'tree> {
  index: NodePtr,
  chain: &'tree Blockchain
}

impl<'tree> Iterator<&'tree BlockchainNode> for BlockIter<'tree> {
  fn next(&mut self) -> Option<&'tree BlockchainNode> {
    match self.index.clone() {
      Some(rc) => {
        use core::mem::transmute;
        self.index = rc.next().clone();
        // This transmute is just to extend the lifetime of rc.block
        // There is unsafety here because we need to be assured that
        // another copy of the rc (presumably the one in the tree)
        // exists and will live as long as 'tree.
        Some(unsafe { transmute(&*rc) } )
      },
      None => None
    }
  }
}

impl<'tree> Iterator<&'tree BlockchainNode> for RevBlockIter<'tree> {
  fn next(&mut self) -> Option<&'tree BlockchainNode> {
    match self.index.clone() {
      Some(rc) => {
        use core::mem::transmute;
        self.index = rc.prev(self.tree).clone();
        // This transmute is just to extend the lifetime of rc.block
        // There is unsafety here because we need to be assured that
        // another copy of the rc (presumably the one in the tree)
        // exists and will live as long as 'tree.
        Some(unsafe { transmute(&*rc) } )
      },
      None => None
    }
  }
}

impl<'tree> Iterator<&'tree Block> for RevStaleBlockIter<'tree> {
  fn next(&mut self) -> Option<&'tree Block> { 
    match self.index.clone() {
      Some(rc) => {
        use core::mem::transmute;
        let next_index = rc.prev(&self.chain.tree);

        // Check if the next block is going to be on the main chain
        if next_index.is_some() &&
           next_index.get_ref().next().get_ref().block.header != rc.block.header &&
           next_index.get_ref().is_on_main_chain(self.chain) {
          self.index = None;
        } else {
          self.index = next_index.clone();
        }
        // This transmute is just to extend the lifetime of rc.block
        // There is unsafety here because we need to be assured that
        // another copy of the rc (presumably the one in the tree)
        // exists and will live as long as 'tree.
        Some(unsafe { transmute(&rc.block) } )
      },
      None => None
    }
  }
}

/// This function emulates the GetCompact(SetCompact(n)) in the satoshi code,
/// which drops the precision to something that can be encoded precisely in
/// the nBits block header field. Savour the perversity. This is in Bitcoin
/// consensus code. What. The. Fuck.
fn satoshi_the_precision(n: &Uint256) -> Uint256 {
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
  pub fn new(genesis: Block) -> Blockchain {
    let genhash = genesis.header.hash();
    let rc_gen = Rc::new(BlockchainNode {
      total_work: Zero::zero(),
      required_difficulty: genesis.header.target(),
      block: genesis,
      height: 0,
      has_txdata: true,
      prev: RefCell::new(None),
      next: RefCell::new(None)
    });
    Blockchain {
      tree: {
        let mut pat = PatriciaTree::new();
        pat.insert(&genhash.as_uint256(), 256, rc_gen.clone());
        pat
      },
      best_hash: genhash,
      genesis_hash: genhash,
      best_tip: rc_gen,
    }
  }

  fn replace_txdata(&mut self, hash: &Uint256, txdata: Vec<Transaction>, has_txdata: bool) -> bool {
    match self.tree.lookup_mut(hash, 256) {
      Some(existing_block) => {
        unsafe {
          // existing_block is an Rc. Rust will not let us mutate it under
          // any circumstances, since if it were to be reallocated, then
          // all other references to it would be destroyed. However, we
          // just need a mutable pointer to the txdata vector; by calling
          // Vec::clone_from() rather than assigning, we can be assured that
          // no reallocation can occur, since clone_from() takes an &mut self,
          // which it does not own and therefore cannot move.
          //
          // To be clear: there will undoubtedly be some reallocation within
          // the Vec itself. We don't care about this. What we care about is
          // that the Vec (and more pointedly, its containing struct) does not
          // move, since this would invalidate the Rc that we are snookering.
          use std::mem::{forget, transmute};
          let mutable_vec: &mut Vec<Transaction> = transmute(&existing_block.block.txdata);
          mutable_vec.clone_from(&txdata);
          // If mutable_vec went out of scope unhindered, it would deallocate
          // the Vec it points to, since Rust assumes that a mutable vector
          // is a unique reference (and this one is definitely not).
          forget(mutable_vec);
          // Do the same thing with the txdata flac
          let mutable_bool: &mut bool = transmute(&existing_block.has_txdata);
          *mutable_bool = has_txdata;
          forget(mutable_bool);
        }
        return true
      },
      None => return false
    }
  }

  /// Locates a block in the chain and overwrites its txdata
  pub fn add_txdata(&mut self, block: Block) -> bool {
    self.replace_txdata(&block.header.hash().as_uint256(), block.txdata, true)
  }

  /// Locates a block in the chain and removes its txdata
  pub fn remove_txdata(&mut self, hash: Sha256dHash) -> bool {
    self.replace_txdata(&hash.as_uint256(), vec![], false)
  }

  /// Adds a block header to the chain
  pub fn add_header(&mut self, header: BlockHeader) -> bool {
    self.real_add_block(Block { header: header, txdata: vec![] }, false)
  }

  /// Adds a block to the chain
  pub fn add_block(&mut self, block: Block) -> bool {
    self.real_add_block(block, true)
  }

  fn real_add_block(&mut self, block: Block, has_txdata: bool) -> bool {
    // get_prev optimizes the common case where we are extending the best tip
    fn get_prev<'a>(chain: &'a Blockchain, hash: Sha256dHash) -> Option<&'a Rc<BlockchainNode>> {
      if hash == chain.best_hash { return Some(&chain.best_tip); }
      chain.tree.lookup(&hash.as_uint256(), 256)
    }
    // Check for multiple inserts (bitcoind from c9a09183 to 3c85d2ec doesn't
    // handle locator hashes properly and may return blocks multiple times,
    // and this may also happen in case of a reorg.
    if self.tree.lookup(&block.header.hash().as_uint256(), 256).is_some() {
      println!("Warning: tried to add block {} twice!", block.header.hash());
      return true;
    }
    // Construct node, if possible
    let rc_block = match get_prev(self, block.header.prev_blockhash) {
      Some(prev) => {
        let difficulty =
          // Compute required difficulty if this is a diffchange block
          if (prev.height + 1) % DIFFCHANGE_INTERVAL == 0 {
            // Scan back DIFFCHANGE_INTERVAL blocks
            let mut scan = prev.clone();
            for _ in range(0, DIFFCHANGE_INTERVAL - 1) {
              scan = scan.prev(&self.tree).unwrap();
            }
            // Get clamped timespan between first and last blocks
            let timespan = match prev.block.header.time - scan.block.header.time {
              n if n < DIFFCHANGE_TIMESPAN / 4 => DIFFCHANGE_TIMESPAN / 4,
              n if n > DIFFCHANGE_TIMESPAN * 4 => DIFFCHANGE_TIMESPAN * 4,
              n => n
            };
            // Compute new target
            let mut target = prev.block.header.target();
            target = target.mul_u32(timespan);
            target = target / FromPrimitive::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
            // Clamp below MAX_TARGET (difficulty 1)
            let max = max_target();
            if target > max { target = max };
            // Compactify (make expressible in the 8+24 nBits float format
            satoshi_the_precision(&target)
          } else {
          // Otherwise just use the last block's difficulty
             prev.required_difficulty
          };
        // Create node
        let ret = Rc::new(BlockchainNode {
          total_work: block.header.work().add(&prev.total_work),
          block: block,
          required_difficulty: difficulty,
          height: prev.height + 1,
          has_txdata: has_txdata,
          prev: RefCell::new(Some(prev.clone())),
          next: RefCell::new(None)
        });
        prev.set_next(ret.clone());
        ret
      },
      None => {
        println!("TODO: couldn't add block");
        return false;
      }
    };

    // spv validate the block
    if !rc_block.block.header.spv_validate(&rc_block.required_difficulty) {
      return false;
    }

    // Insert the new block
    self.tree.insert(&rc_block.block.header.hash().as_uint256(), 256, rc_block.clone());
    // Replace the best tip if necessary
    if rc_block.total_work > self.best_tip.total_work {
      self.set_best_tip(rc_block);
    }
    return true;
  }

  /// Sets the best tip (not public)
  fn set_best_tip(&mut self, tip: Rc<BlockchainNode>) {
    let old_best = self.best_tip.clone();
    // Set best
    self.best_hash = tip.hash();
    self.best_tip = tip;
    // Fix next links
    let mut scan = self.best_tip.clone();
    let mut prev = self.best_tip.prev(&self.tree);
    // Scan backward
    loop {
      // If we hit the old best, there is no need to reorg
      if scan.block.header == old_best.block.header {
        break;
      }
      // If we hit the genesis, stop
      if prev.is_none() {
        println!("Warning: reorg past the genesis. This is a bug.");
        break;
      }
      // If we hit something pointing along the wrong chain, this is
      // a branch point at which we are reorg'ing
      if prev.get_ref().next().is_none() ||
         prev.get_ref().next().get_ref().block.header != scan.block.header {
        prev.get_mut_ref().set_next(scan);
      }
      scan = prev.clone().unwrap();
      prev = prev.unwrap().prev(&self.tree);
    }
  }

  /// Returns the best tip
  pub fn best_tip<'a>(&'a self) -> &'a Block {
    &self.best_tip.block
  }

  /// Returns the best tip's blockhash
  pub fn best_tip_hash(&self) -> Sha256dHash {
    self.best_hash
  }

  /// Returns an array of locator hashes used in `getheaders` messages
  pub fn locator_hashes(&self) -> Vec<Sha256dHash> {
    LocatorHashIter::new(self.best_tip.clone(), &self.tree).collect()
  }

  /// An iterator over all blocks in the chain starting from `start_hash`
  pub fn iter<'a>(&'a self, start_hash: Sha256dHash) -> BlockIter<'a> {
    BlockIter {
      index: self.tree.lookup(&start_hash.as_uint256(), 256).map(|rc| rc.clone()),
      marker: marker::ContravariantLifetime::<'a>
    }
  }

  /// An iterator over all blocks in reverse order to the genesis, starting with `start_hash`
  pub fn rev_iter<'a>(&'a self, start_hash: Sha256dHash) -> RevBlockIter<'a> {
    RevBlockIter {
      index: self.tree.lookup(&start_hash.as_uint256(), 256).map(|rc| rc.clone()),
      tree: &self.tree
    }
  }

  /// An iterator over all blocks -not- in the best chain, in reverse order, starting from `start_hash`
  pub fn rev_stale_iter<'a>(&'a self, start_hash: Sha256dHash) -> RevStaleBlockIter<'a> {
    let mut start = self.tree.lookup(&start_hash.as_uint256(), 256).map(|rc| rc.clone());
    // If we are already on the main chain, we have a dead iterator
    if start.is_some() && start.get_ref().is_on_main_chain(self) {
      start = None;
    }
    // Return iterator
    RevStaleBlockIter { 
      index: start,
      chain: self
    }
  }
}

#[cfg(test)]
mod tests {
  use std::prelude::*;
  use std::io::IoResult;

  use blockdata::blockchain::Blockchain;
  use blockdata::constants::genesis_block;
  use network::serialize::Serializable;

  #[test]
  fn blockchain_serialize_test() {
    let empty_chain = Blockchain::new(genesis_block());
    assert_eq!(empty_chain.best_tip.hash().serialize(), genesis_block().header.hash().serialize());

    let serial = empty_chain.serialize();
    assert_eq!(serial, empty_chain.serialize_iter().collect());

    let deserial: IoResult<Blockchain> = Serializable::deserialize(serial.iter().map(|n| *n));
    assert!(deserial.is_ok());
    let read_chain = deserial.unwrap();
    assert_eq!(read_chain.best_tip.hash().serialize(), genesis_block().header.hash().serialize());
  }
}



