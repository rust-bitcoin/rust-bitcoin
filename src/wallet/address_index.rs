// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Address Index
//!
//! Maintains an index from addresses to unspent outputs. It reduces size by
//! checking that the first byte of HMAC(wallet key, address outscript) is
//! zero, so that the index will be 1/256th the size of the utxoset in RAM.
//!

use std::collections::HashMap;
use collections::hash::sip::hash_with_keys;

use blockdata::transaction::{TxOut, PayToPubkeyHash};
use blockdata::utxoset::UtxoSet;
use blockdata::script::Script;
use network::constants::Network;
use wallet::address::Address;
use wallet::wallet::Wallet;
use util::hash::Sha256dHash;

/// An address index
#[deriving(Clone, PartialEq, Eq, Show)]
pub struct AddressIndex {
  index: HashMap<Script, Vec<(Sha256dHash, uint, TxOut, uint)>>,
  network: Network,
  k1: u64,
  k2: u64
}

impl AddressIndex {
  /// Creates a new address index from a wallet (which provides an authenticated
  /// hash function for prefix filtering) and UTXO set (which is what gets filtered).
  pub fn new(utxo_set: &UtxoSet, wallet: &Wallet) -> AddressIndex {
    let (k1, k2) = wallet.siphash_key();
    let mut ret = AddressIndex {
      index: HashMap::with_capacity(utxo_set.n_utxos() / 256),
      network: wallet.network(),
      k1: k1,
      k2: k2
    };
    for (key, idx, txo, height) in utxo_set.iter() {
      if ret.admissible_txo(txo) {
          let pubkey = txo.script_pubkey.clone();
          let insert = (key, idx, txo.clone(), height);
          if ret.index.contains_key(&pubkey) {
              let vec = ret.index.get_mut(&pubkey);
              vec.push(insert);
          } else {
              ret.index.insert(pubkey, vec![insert]);
          }
      }
    }
    ret
  }

  /// A filtering function used for creating a small address index.
  #[inline]
  pub fn admissible_address(&self, addr: &Address) -> bool {
    hash_with_keys(self.k1, self.k2, &addr.as_slice()) & 0xFF == 0
  }

  /// A filtering function used for creating a small address index.
  #[inline]
  pub fn admissible_txo(&self, out: &TxOut) -> bool {
    match out.classify(self.network) {
      PayToPubkeyHash(addr) => self.admissible_address(&addr),
      _ => false
    }
  }

  /// Lookup a txout by its scriptpubkey. Returns a slice because there
  /// may be more than one for any given scriptpubkey.
  #[inline]
  pub fn find_by_script<'a>(&'a self, pubkey: &Script) -> &'a [(Sha256dHash, uint, TxOut, uint)] {
    self.index.find(pubkey).map(|v| v.as_slice()).unwrap_or(&[])
  }
}


