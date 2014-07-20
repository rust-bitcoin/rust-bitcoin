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

use std::collections::HashMap;
use std::io::IoResult;
use std::mem;

use blockdata::transaction::{Transaction, TxOut};
use blockdata::constants::genesis_block;
use blockdata::block::Block;
use network::constants::Network;
use network::serialize::{Serializable, SerializeIter};
use util::hash::{DumbHasher, Sha256dHash};
use util::uint::Uint128;
use util::thinvec::ThinVec;

/// Vector of outputs; None indicates a nonexistent or already spent output
type UtxoNode = ThinVec<Option<Box<TxOut>>>;

/// The UTXO set
pub struct UtxoSet {
  table: HashMap<Uint128, UtxoNode, DumbHasher>,
  last_hash: Sha256dHash,
  // A circular buffer of deleted utxos, grouped by block
  spent_txos: Vec<Vec<Box<TxOut>>>,
  // The last index into the above buffer that was assigned to
  spent_idx: u64,
  n_utxos: u64
}

impl_serializable!(UtxoSet, last_hash, n_utxos, spent_txos, spent_idx, table)

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
      n_utxos: 0
    }
  }

  /// Add all the UTXOs of a transaction to the set
  fn add_utxos(&mut self, tx: &Transaction) -> bool {
    let txid = tx.bitcoin_hash();
    // Locate node if it's already there
    let mut new_node = ThinVec::with_capacity(tx.output.len() as u32);
    for (vout, txo) in tx.output.iter().enumerate() {
      // Unsafe since we are not uninitializing the old data in the vector
      unsafe { new_node.init(vout as uint, Some(box txo.clone())); }
    }
    // TODO: insert/lookup should return a Result which we pass along
    if self.table.insert(txid.as_uint128(), new_node) {
      self.n_utxos += tx.output.len() as u64;
      return true;
    }
    return false;
  }

  /// Remove a UTXO from the set and return it
  fn take_utxo(&mut self, txid: Sha256dHash, vout: u32) -> Option<Box<TxOut>> {
    // This whole function has awkward scoping thx to lexical borrow scoping :(
    let (ret, should_delete) = {
      // Locate the UTXO, failing if not found
      let node = match self.table.find_mut(&txid.as_uint128()) {
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
      self.table.remove(&txid.as_uint128());
    }

    self.n_utxos -= if ret.is_some() { 1 } else { 0 };
    ret
  }

  /// Get a reference to a UTXO in the set
  pub fn get_utxo<'a>(&'a mut self, txid: Sha256dHash, vout: u32) -> Option<&'a Box<TxOut>> {
    // Locate the UTXO, failing if not found
    let node = match self.table.find_mut(&txid.as_uint128()) {
      Some(node) => node,
      None => return None
    };
    // Check that this specific output is there
    if vout as uint >= node.len() { return None; }
    let replace = unsafe { node.get(vout as uint) };
    replace.as_ref()
  }

  /// Apply the transactions contained in a block
  pub fn update(&mut self, block: &Block) -> bool {
    // Make sure we are extending the UTXO set in order
    if self.last_hash != block.header.prev_blockhash {
      return false;
    }

    // Set the next hash immediately so that if anything goes wrong,
    // we can rewind from the point that we're at.
    self.last_hash = block.header.bitcoin_hash();
    let spent_idx = self.spent_idx as uint;
    self.spent_idx = (self.spent_idx + 1) % self.spent_txos.len() as u64;
    self.spent_txos.get_mut(spent_idx).clear();

    let mut skipped_genesis = false;
    for tx in block.txdata.iter() {
      // Put the removed utxos into the stxo cache. Note that the order that
      // they are pushed onto the stxo cache -must- match the order of the
      // txos in the block so that rewind() will rewind them properly.
      if skipped_genesis {
        self.spent_txos.get_mut(spent_idx).reserve_additional(tx.input.len());
        for input in tx.input.iter() {
          let taken = self.take_utxo(input.prev_hash, input.prev_index);
          match taken {
            Some(txo) => { self.spent_txos.get_mut(spent_idx).push(txo); }
            None => { self.rewind(block); }
          }
        }
      }
      skipped_genesis = true;

      // Add outputs
      //   This will fail in the case of a duplicate transaction. This can only
      //   happen with coinbases, and in this case the block is invalid, -except-
      //   for two historic blocks which appeared in the blockchain before the
      //   dupes were noticed. See bitcoind commit `ab91bf39` and BIP30.
      // TODO: add a unit test for these blocks.
      if !self.add_utxos(tx) {
        let blockhash = block.header.bitcoin_hash().le_hex_string();
        if blockhash == "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec".to_string() ||
           blockhash == "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721".to_string() {
          // For these specific blocks, overwrite the old UTXOs.
          self.table.remove(&tx.bitcoin_hash().as_uint128());
          self.add_utxos(tx);
        } else {
          // Otherwise fail the block
          self.rewind(block);
          return false;
        }
      }
    }
    // If we made it here, success!
    true
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
        self.take_utxo(txhash, n as u32);
      }

      // Read deleted txouts -- note that we are trusting that these are
      // in the same order in our cache as they were in the original block.
      if skipped_genesis {

        let mut extract_vec = vec![];
        mem::swap(&mut extract_vec, self.spent_txos.get_mut(self.spent_idx as uint));
        for (txo, inp) in extract_vec.move_iter().zip(tx.input.iter()) {
          // Remove the tx's utxo list and patch the txo into place
          let new_node =
              match self.table.pop(&inp.prev_hash.as_uint128()) {
                Some(mut thinvec) => {
                  let old_len = thinvec.len() as u32;
                  if old_len < inp.prev_index + 1 {
                    thinvec.reserve(inp.prev_index + 1);
                    for i in range(old_len, inp.prev_index + 1) {
                      unsafe { thinvec.init(i as uint, None); }
                    }
                  }
                  unsafe { *thinvec.get_mut(inp.prev_index as uint) = Some(txo); }
                  thinvec
                }
                None => {
                  let mut thinvec = ThinVec::with_capacity(inp.prev_index + 1);
                  for i in range(0, inp.prev_index + 1) {
                    unsafe { thinvec.init(i as uint, None); }
                  }
                  unsafe { *thinvec.get_mut(inp.prev_index as uint) = Some(txo); }
                  thinvec
                }
              };
          // Ram it back into the tree
          self.table.insert(inp.prev_hash.as_uint128(), new_node);
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
}

#[cfg(test)]
mod tests {
  use std::prelude::*;
  use std::io::IoResult;
  use serialize::hex::FromHex;

  use blockdata::block::Block;
  use blockdata::utxoset::UtxoSet;
  use network::constants::Bitcoin;
  use network::serialize::Serializable;

  #[test]
  fn utxoset_serialize_test() {
    let mut empty_set = UtxoSet::new(Bitcoin, 100);

    let new_block: Block = Serializable::deserialize("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000".from_hex().unwrap().iter().map(|n| *n)).unwrap();

    // Make sure we can't add the block directly, since we are missing the inputs
    assert!(!empty_set.update(&new_block));
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
        assert_eq!(empty_set.get_utxo(hash, n), Some(&box out.clone()));
      }
    }

    // Check again that we can't add the block, and that this doesn't mess up the
    // existing UTXOs
    assert!(!empty_set.update(&new_block));
    assert_eq!(empty_set.n_utxos(), 2);
    for tx in new_block.txdata.iter() {
      let hash = tx.bitcoin_hash();
      for (n, out) in tx.output.iter().enumerate() {
        let n = n as u32;
        assert_eq!(empty_set.get_utxo(hash, n), Some(&box out.clone()));
      }
    }

    // Serialize/deserialize the resulting UTXO set
    let serial = empty_set.serialize();
    assert_eq!(serial, empty_set.serialize_iter().collect());

    let deserial: IoResult<UtxoSet> = Serializable::deserialize(serial.iter().map(|n| *n));
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
        assert_eq!(ret, Some(box out.clone()));
        // Try double-take
        assert_eq!(read_set.take_utxo(hash, n), None);
      }
    }

    let deserial_again: IoResult<UtxoSet> = Serializable::deserialize(serial.iter().map(|n| *n));
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



