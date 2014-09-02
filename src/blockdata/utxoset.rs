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

//! # UTXO Set
//!
//! This module provides the structures and functions to maintain an
//! index of UTXOs.
//!

use std::cmp;
use std::collections::HashMap;
use std::collections::hashmap::Entries;
use std::mem;
use std::os::num_cpus;
use std::sync::Future;
use std::num::Zero;

use blockdata::transaction::{Transaction, TxOut};
use blockdata::transaction::{TransactionError, InputNotFound};
use blockdata::constants::genesis_block;
use blockdata::block::Block;
use network::constants::Network;
use network::serialize::BitcoinHash;
use util::hash::{DumbHasher, Sha256dHash};
use util::uint::Uint128;
use util::thinvec::ThinVec;

/// The amount of validation to do when updating the UTXO set
#[deriving(PartialEq, Eq, PartialOrd, Ord, Clone, Show)]
pub enum ValidationLevel {
  /// Blindly update the UTXO set (NOT recommended)
  NoValidation,
  /// Check that the blocks are at least in the right order
  ChainValidation,
  /// Check that any inputs are actually txouts in the set
  TxoValidation,
  /// Execute the scripts and ensure they pass
  ScriptValidation
}

/// An error returned from a UTXO set operation
#[deriving(PartialEq, Eq, Clone, Show)]
pub enum UtxoSetError {
  /// prevhash of the new block is not the hash of the old block (expected, actual)
  BadPrevHash(Sha256dHash, Sha256dHash),
  /// A TXID was duplicated
  DuplicatedTxid(Sha256dHash),
  /// A tx was invalid (txid, error)
  InvalidTx(Sha256dHash, TransactionError),
}

/// Vector of outputs; None indicates a nonexistent or already spent output
type UtxoNode = ThinVec<Option<TxOut>>;

/// An iterator over UTXOs
pub struct UtxoIterator<'a> {
  tx_iter: Entries<'a, Uint128, UtxoNode>,
  current_key: Uint128,
  current: Option<&'a UtxoNode>,
  tx_index: uint
}

impl<'a> Iterator<(Uint128, uint, &'a TxOut)> for UtxoIterator<'a> {
  fn next(&mut self) -> Option<(Uint128, uint, &'a TxOut)> {
    while self.current.is_some() {
      let current = self.current.unwrap();
      while self.tx_index < current.len() {
        self.tx_index += 1;
        if unsafe { current.get(self.tx_index - 1) }.is_some() {
          return Some((self.current_key,
                      self.tx_index,
                      unsafe { current.get(self.tx_index - 1) }.as_ref().unwrap()));
        }
      }
      match self.tx_iter.next() {
        Some((&x, y)) => {
          self.tx_index = 0;
          self.current_key = x;
          self.current = Some(y);
        }
        None => { self.current = None; }
      }
    }
    return None;
  }
}

/// The UTXO set
pub struct UtxoSet {
  table: HashMap<Uint128, UtxoNode, DumbHasher>,
  last_hash: Sha256dHash,
  // A circular buffer of deleted utxos, grouped by block
  spent_txos: Vec<Vec<((Sha256dHash, u32), TxOut)>>,
  // The last index into the above buffer that was assigned to
  spent_idx: u64,
  n_utxos: u64,
  n_pruned: u64
}

impl_consensus_encoding!(UtxoSet, last_hash, n_utxos, n_pruned, spent_txos, spent_idx, table)

impl UtxoSet {
  /// Constructs a new UTXO set
  pub fn new(network: Network, rewind_limit: uint) -> UtxoSet {
    // There is in fact a transaction in the genesis block, but the Bitcoin
    // reference client does not add its sole output to the UTXO set. We
    // must follow suit, otherwise we will accept a transaction spending it
    // while the reference client won't, causing us to fork off the network.
    UtxoSet {
      table: HashMap::with_hasher(DumbHasher),
      last_hash: genesis_block(network).header.bitcoin_hash(),
      spent_txos: Vec::from_elem(rewind_limit, vec![]),
      spent_idx: 0,
      n_utxos: 0,
      n_pruned: 0
    }
  }

  /// Add all the UTXOs of a transaction to the set
  fn add_utxos(&mut self, tx: &Transaction) -> Option<UtxoNode> {
    let txid = tx.bitcoin_hash();
    // Locate node if it's already there
    let new_node = unsafe {
      let mut new_node = ThinVec::with_capacity(tx.output.len() as u32);
      for (vout, txo) in tx.output.iter().enumerate() {
        // Unsafe since we are not uninitializing the old data in the vector
        if txo.script_pubkey.is_provably_unspendable() {
          new_node.init(vout as uint, None);
          self.n_utxos -= 1;
          self.n_pruned += 1;
        } else {
          new_node.init(vout as uint, Some(txo.clone()));
        }
      }
      new_node
    };
    // Get the old value, if any (this is suprisingly possible, c.f. BIP30
    // and the other comments in this file referring to it)
    let ret = self.table.swap(txid.into_le().low_128(), new_node);
    if ret.is_none() {
      self.n_utxos += tx.output.len() as u64;
    }
    ret
  }

  /// Remove a UTXO from the set and return it
  fn take_utxo(&mut self, txid: Sha256dHash, vout: u32) -> Option<TxOut> {
    // This whole function has awkward scoping thx to lexical borrow scoping :(
    let (ret, should_delete) = {
      // Locate the UTXO, failing if not found
      let node = match self.table.find_mut(&txid.into_le().low_128()) {
        Some(node) => node,
        None => return None
      };

      let ret = {
        // Check that this specific output is there
        if vout as uint >= node.len() { return None; }
        let replace = unsafe { node.get_mut(vout as uint) };
        replace.take()
      };

      let should_delete = node.iter().filter(|slot| slot.is_some()).count() == 0;
      (ret, should_delete)
    };

    // Delete the whole node if it is no longer being used
    if should_delete {
      self.table.remove(&txid.into_le().low_128());
    }

    self.n_utxos -= if ret.is_some() { 1 } else { 0 };
    ret
  }

  /// Get a reference to a UTXO in the set
  pub fn get_utxo<'a>(&'a self, txid: Sha256dHash, vout: u32) -> Option<&'a TxOut> {
    // Locate the UTXO, failing if not found
    let node = match self.table.find(&txid.into_le().low_128()) {
      Some(node) => node,
      None => return None
    };
    // Check that this specific output is there
    if vout as uint >= node.len() { return None; }
    let replace = unsafe { node.get(vout as uint) };
    replace.as_ref()
  }

  /// Apply the transactions contained in a block
  pub fn update(&mut self, block: &Block, validation: ValidationLevel)
                -> Result<(), UtxoSetError> {
    // Make sure we are extending the UTXO set in order
    if validation >= ChainValidation &&
       self.last_hash != block.header.prev_blockhash {
      return Err(BadPrevHash(self.last_hash, block.header.prev_blockhash));
    }

    // Set the next hash immediately so that if anything goes wrong,
    // we can rewind from the point that we're at.
    self.last_hash = block.header.bitcoin_hash();
    let spent_idx = self.spent_idx as uint;
    self.spent_idx = (self.spent_idx + 1) % self.spent_txos.len() as u64;
    self.spent_txos.get_mut(spent_idx).clear();

    // Add all the utxos so that we can have chained transactions within the
    // same block. (Note that Bitcoin requires chained transactions to be in
    // the correct order, which we do not check, so we are minorly too permissive.
    // TODO this is a consensus bug.)
    for tx in block.txdata.iter() {
      let txid = tx.bitcoin_hash();
      // Add outputs -- add_utxos returns the original transaction if this is a dupe.
      //   Note that this can only happen with coinbases, and in this case the block
      //   is invalid, -except- for two historic blocks which appeared in the
      //   blockchain before the dupes were noticed.
      //   See bitcoind commit `ab91bf39` and BIP30.
      match self.add_utxos(tx) {
        Some(mut replace) => {
          let blockhash = block.header.bitcoin_hash().be_hex_string();
          if blockhash == "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec".to_string() ||
             blockhash == "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721".to_string() {
            // For these specific blocks, overwrite the old UTXOs.
            // (Actually add_utxos() already did this, so we do nothing.)
          } else {
            // Otherwise put the replaced txouts into the `deleted` cache
            // so that rewind will put them back.
            self.spent_txos.get_mut(spent_idx).reserve_additional(replace.len());
            for (n, input) in replace.mut_iter().enumerate() {
              match input.take() {
                Some(txo) => { self.spent_txos.get_mut(spent_idx).push(((txid, n as u32), txo)); }
                None => {}
              }
            }
            // Otherwise fail the block
            self.rewind(block);
            return Err(DuplicatedTxid(txid));
          }
        }
        // Didn't replace anything? Good.
        None => {}
      }
    }

    // If we are validating scripts, do all that now in parallel
    if validation >= ScriptValidation {
      let mut future_vec = Vec::with_capacity(block.txdata.len() - 1);
      // skip the genesis since we don't validate this script. (TODO this might
      // be a consensus bug since we don't even check that the opcodes make sense.)
      let n_threads = cmp::min(block.txdata.len() - 1, num_cpus());
      for j in range(0, n_threads) {
        let n_elems = block.txdata.len() - 1;
        let start = 1 + j * n_elems / n_threads;
        let end = cmp::min(n_elems, 1 + (j + 1) * n_elems / n_threads);

        let s = self as *mut _ as *const UtxoSet;
        let txes = &block.txdata as *const _;
        future_vec.push(Future::spawn(proc() {
          let txes = unsafe {&*txes};
          for tx in txes.slice(start, end).iter() {
            match tx.validate(unsafe {&*s}) {
              Ok(_) => {},
              Err(e) => { return Err(InvalidTx(tx.bitcoin_hash(), e)); }
            }
          }
          Ok(())
        }));
      }
      // Return the last error since we need to finish every future before
      // leaving this function, and given that, it's easier to return the last.
      let mut last_error = Ok(());
      for res in future_vec.mut_iter().map(|f| f.get()) {
        if res.is_err() {
          last_error = res;
        }
      }
      if last_error.is_err() {
        return last_error;
      }
    }

    for tx in block.txdata.iter().skip(1) {
      let txid = tx.bitcoin_hash();
      // Put the removed utxos into the stxo cache, in case we need to rewind
      self.spent_txos.get_mut(spent_idx).reserve_additional(tx.input.len());
      for (n, input) in tx.input.iter().enumerate() {
        let taken = self.take_utxo(input.prev_hash, input.prev_index);
        match taken {
          Some(txo) => { self.spent_txos.get_mut(spent_idx).push(((txid, n as u32), txo)); }
          None => {
            if validation >= TxoValidation {
              self.rewind(block);
              return Err(InvalidTx(txid,
                                   InputNotFound(input.prev_hash, input.prev_index)));
            }
          }
        }
      }
    }
    // If we made it here, success!
    Ok(())
  }

  /// Unapply the transactions contained in a block
  pub fn rewind(&mut self, block: &Block) -> bool {
    // Make sure we are rewinding the latest block
    if self.last_hash != block.header.bitcoin_hash() {
      return false;
    }

    // We deliberately do no error checking here, since we may be rewinding
    // from halfway through the new block addition, in which case many of
    // the utxos we try to remove may be missing; the ones we try to add,
    // we stored ourselves when we removed them, so they won't be unaddable
    // for any reason.
    // Plus we don't care too much about efficiency, not many blocks should
    // get rewound.

    // Delete added txouts
    let mut skipped_genesis = false;
    for tx in block.txdata.iter() {
      let txhash = tx.bitcoin_hash();
      for n in range(0, tx.output.len()) {
        // Just bomb out the whole transaction
        // TODO: this does not conform to BIP30: if a duplicate txid occurs,
        //       the block will be (rightly) rejected, causing it to be
        //       unwound. But when we get here, we can't see the duplicate,
        //       so we wind up deleting the old txid! This is very bad, and
        //       if it occurs, an affected user will have to recreate his
        //       whole UTXO index to get the original txid back.
        self.take_utxo(txhash, n as u32);
      }

      // Read deleted txouts
      if skipped_genesis {
        let mut extract_vec = vec![];
        mem::swap(&mut extract_vec, self.spent_txos.get_mut(self.spent_idx as uint));
        for ((txid, n), txo) in extract_vec.move_iter() {
          // Remove the tx's utxo list and patch the txo into place
          let new_node =
              match self.table.pop(&txid.into_le().low_128()) {
                Some(mut thinvec) => {
                  let old_len = thinvec.len() as u32;
                  if old_len < n + 1 {
                    unsafe {
                      thinvec.reserve(n + 1);
                      for i in range(old_len, n + 1) {
                        thinvec.init(i as uint, None);
                      }
                    }
                  }
                  unsafe { *thinvec.get_mut(n as uint) = Some(txo); }
                  thinvec
                }
                None => {
                  unsafe {
                    let mut thinvec = ThinVec::with_capacity(n + 1);
                    for i in range(0, n) {
                      thinvec.init(i as uint, None);
                    }
                    thinvec.init(n as uint, Some(txo));
                    thinvec
                  }
                }
              };
          // Ram it back into the tree
          self.table.insert(txid.into_le().low_128(), new_node);
        }
      }
      skipped_genesis = true;
    }

    // Decrement mod the spent txo cache size
    self.spent_idx = (self.spent_idx + self.spent_txos.len() as u64 - 1) %
                       self.spent_txos.len() as u64;
    self.last_hash = block.header.prev_blockhash;
    return true;
  }

  /// Get the hash of the last block added to the utxo set
  pub fn last_hash(&self) -> Sha256dHash {
    self.last_hash
  }

  /// Get the number of UTXOs in the set
  pub fn n_utxos(&self) -> uint {
    self.n_utxos as uint
  }

  /// Get the number of UTXOs ever pruned from the set (this is not updated
  /// during reorgs, so it may return a higher number than is realistic).
  pub fn n_pruned(&self) -> uint {
    self.n_pruned as uint
  }

  /// Get an iterator over all UTXOs
  pub fn iter<'a>(&'a self) -> UtxoIterator<'a> {
    let mut iter = self.table.iter();
    let first = iter.next();
    match first {
      Some((&key, val)) => UtxoIterator {
          current_key: key,
          current: Some(val),
          tx_iter: iter,
          tx_index: 0
        },
      None => UtxoIterator {
          current_key: Zero::zero(),
          current: None,
          tx_iter: iter,
          tx_index: 0
        }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::prelude::*;
  use std::io::IoResult;
  use serialize::hex::FromHex;

  use super::{UtxoSet, TxoValidation};

  use blockdata::block::Block;
  use network::constants::Bitcoin;
  use network::serialize::{BitcoinHash, deserialize, serialize};

  #[test]
  fn utxoset_serialize_test() {
    let mut empty_set = UtxoSet::new(Bitcoin, 100);

    let new_block: Block = deserialize("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000".from_hex().unwrap()).unwrap();

    // Make sure we can't add the block directly, since we are missing the inputs
    assert!(empty_set.update(&new_block, TxoValidation).is_err());
    assert_eq!(empty_set.n_utxos(), 0);
    // Add the block manually so that we'll have some UTXOs for the rest of the test
    for tx in new_block.txdata.iter() {
      empty_set.add_utxos(tx);
    }
    empty_set.last_hash = new_block.header.bitcoin_hash();

    // Check that all the UTXOs were added
    assert_eq!(empty_set.n_utxos(), 2);
    for tx in new_block.txdata.iter() {
      let hash = tx.bitcoin_hash();
      for (n, out) in tx.output.iter().enumerate() {
        let n = n as u32;
        assert_eq!(empty_set.get_utxo(hash, n), Some(&out.clone()));
      }
    }

    // Check again that we can't add the block, and that this doesn't mess up the
    // existing UTXOs
    assert!(empty_set.update(&new_block, TxoValidation).is_err());
    assert_eq!(empty_set.n_utxos(), 2);
    for tx in new_block.txdata.iter() {
      let hash = tx.bitcoin_hash();
      for (n, out) in tx.output.iter().enumerate() {
        let n = n as u32;
        assert_eq!(empty_set.get_utxo(hash, n), Some(&out.clone()));
      }
    }

    // Serialize/deserialize the resulting UTXO set
    let serial = serialize(&empty_set).unwrap();

    let deserial: IoResult<UtxoSet> = deserialize(serial.clone());
    assert!(deserial.is_ok());

    // Check that all outputs are there
    let mut read_set = deserial.unwrap();
    for tx in new_block.txdata.iter() {
      let hash = tx.bitcoin_hash();

      for (n, out) in tx.output.iter().enumerate() {
        let n = n as u32;
        // Try taking non-existent UTXO
        assert_eq!(read_set.take_utxo(hash, 100 + n), None);
        // Check take of real UTXO
        let ret = read_set.take_utxo(hash, n);
        assert_eq!(ret, Some(out.clone()));
        // Try double-take
        assert_eq!(read_set.take_utxo(hash, n), None);
      }
    }

    let deserial_again: IoResult<UtxoSet> = deserialize(serial);
    let mut read_again = deserial_again.unwrap();
    assert!(read_again.rewind(&new_block));
    assert_eq!(read_again.n_utxos(), 0);
    for tx in new_block.txdata.iter() {
      let hash = tx.bitcoin_hash();

      for n in range(0, tx.output.len()) {
        let n = n as u32;
        let ret = read_again.take_utxo(hash, n);
        assert_eq!(ret, None);
      }
    }
  }
}



