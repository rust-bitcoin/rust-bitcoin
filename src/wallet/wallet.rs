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

//! # Wallet
//!
//! Everything to do with the wallet
//!

use std::collections::HashMap;
use std::default::Default;
use std::io::extensions::u64_from_be_bytes;
use collections::hash::sip::hash_with_keys;

use blockdata::transaction::{PayToPubkeyHash, TxOut};
use network::constants::Network;
use wallet::bip32::{mod, ChildNumber, ExtendedPrivKey, Normal, Hardened};

/// A Wallet error
pub enum Error {
  /// Tried to lookup an account by name, but none was found
  AccountNotFound,
  /// Tried to add an account when one already exists with that name
  DuplicateAccount
}

/// An account
#[deriving(Clone, PartialEq, Eq, Encodable, Decodable, Show)]
pub struct Account {
  name: String,
  internal_path: Vec<ChildNumber>,
  external_path: Vec<ChildNumber>
}

impl Default for Account {
  fn default() -> Account {
    Account {
      name: String::new(),
      internal_path: vec![Hardened(0), Normal(1)],
      external_path: vec![Hardened(0), Normal(0)]
    }
  }
}

/// A wallet
#[deriving(Clone, PartialEq, Eq, Encodable, Decodable, Show)]
pub struct Wallet {
  master: ExtendedPrivKey,
  accounts: HashMap<String, Account>
}

impl Wallet {
  /// Creates a new wallet from a BIP32 seed
  #[inline]
  pub fn from_seed(network: Network, seed: &[u8]) -> Result<Wallet, bip32::Error> {
    let mut accounts = HashMap::new();
    accounts.insert(String::new(), Default::default());

    Ok(Wallet {
      master: try!(ExtendedPrivKey::new_master(network, seed)),
      accounts: accounts
    })
  }

  /// Adds an account to a wallet
  pub fn add_account(&mut self, name: String)
                     -> Result<(), Error> {
    if self.accounts.find(&name).is_some() {
      return Err(DuplicateAccount);
    }

    let idx = self.accounts.len() as u32;
    self.accounts.insert(name.clone(), Account {
      name: name,
      internal_path: vec![Hardened(idx), Normal(1)],
      external_path: vec![Hardened(idx), Normal(0)]
    });
    Ok(())
  }

  /// Returns the network of the wallet
  #[inline]
  pub fn network(&self) -> Network {
    self.master.network
  }

  /// Returns a key suitable for keying hash functions for DoS protection
  #[inline]
  pub fn siphash_key(&self) -> (u64, u64) {
    let ck_slice = self.master.chain_code.as_slice();
    (u64_from_be_bytes(ck_slice, 0, 8),
     u64_from_be_bytes(ck_slice, 8, 8))
  }

  /// A filter used for creating a small address index
  #[inline]
  pub fn might_be_mine(&self, out: &TxOut) -> bool {
    let (k1, k2) = self.siphash_key();
    match out.classify(self.network()) {
      PayToPubkeyHash(addr) => hash_with_keys(k1, k2, &addr.as_slice()) & 0xFF == 0,
      _ => false
    }
  }
}



