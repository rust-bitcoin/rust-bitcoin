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

use blockdata::utxoset::UtxoSet;
use blockdata::script::Script;
use wallet::wallet::Wallet;
use util::uint::Uint128;

/// An address index
#[deriving(Clone, PartialEq, Eq, Show)]
pub struct AddressIndex {
  index: HashMap<Script, (Uint128, uint)>
}

impl AddressIndex {
  /// Creates a new address index from a wallet (which provides an authenticated
  /// hash function for prefix filtering) and UTXO set (which is what gets filtered).
  pub fn new(utxo_set: &UtxoSet, wallet: &Wallet) -> AddressIndex {
    let mut ret = AddressIndex {
      index: HashMap::with_capacity(utxo_set.n_utxos() / 256)
    };
    for (key, idx, txo) in utxo_set.iter() {
      if wallet.might_be_mine(txo) {
        ret.index.insert(txo.script_pubkey.clone(), (key, idx));
      }
    }
    ret
  }
}



