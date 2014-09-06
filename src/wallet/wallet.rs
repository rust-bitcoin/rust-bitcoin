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
use serialize::{Decoder, Decodable, Encoder, Encodable};

use secp256k1::key::PublicKey;

use blockdata::transaction::{PayToPubkeyHash, TxOut};
use network::constants::Network;
use wallet::bip32::{mod, ChildNumber, ExtendedPrivKey, Normal, Hardened};
use wallet::address::Address;

/// A Wallet error
pub enum Error {
  /// Tried to lookup an account by name, but none was found
  AccountNotFound,
  /// Tried to add an account when one already exists with that name
  DuplicateAccount,
  /// An error occured in a BIP32 derivation
  Bip32Error(bip32::Error)
}

/// Each account has two chains, as specified in BIP32
pub enum AccountChain {
  /// Internal addresses are used within the wallet for change, etc,
  /// and in principle every generated one will be used.
  Internal,
  /// External addresses are shared, and might not be used after generatation,
  /// complicating recreating the whole wallet from seed.
  External
}

/// An account
#[deriving(Clone, PartialEq, Eq, Encodable, Decodable, Show)]
pub struct Account {
  name: String,
  internal_path: Vec<ChildNumber>,
  internal_used: Vec<ChildNumber>,
  internal_next: u32,
  external_path: Vec<ChildNumber>,
  external_used: Vec<ChildNumber>,
  external_next: u32
}

impl Default for Account {
  fn default() -> Account {
    Account {
      name: String::new(),
      internal_path: vec![Hardened(0), Normal(1)],
      internal_used: vec![],
      internal_next: 0,
      external_path: vec![Hardened(0), Normal(0)],
      external_used: vec![],
      external_next: 0
    }
  }
}

/// A wallet
#[deriving(Clone, PartialEq, Eq, Show)]
pub struct Wallet {
  master: ExtendedPrivKey,
  accounts: HashMap<String, Account>
}

impl<S: Encoder<E>, E> Encodable<S, E> for Wallet {
  fn encode(&self, s: &mut S) -> Result<(), E> {
    s.emit_struct("wallet", 2, |s| {
      try!(s.emit_struct_field("master", 0, |s| self.master.encode(s)));
      s.emit_struct_field("accounts", 1,
        |s| s.emit_seq(self.accounts.len(), |s| {
          for (_, account) in self.accounts.iter() {
            try!(account.encode(s));
          }
          Ok(())
        }))
    })
  }
}

impl Account {
}

impl<D: Decoder<E>, E> Decodable<D, E> for Wallet {
  fn decode(d: &mut D) -> Result<Wallet, E> { 
    d.read_struct("wallet", 2, |d| {
      Ok(Wallet { 
        master: try!(d.read_struct_field("master", 0, Decodable::decode)),
        accounts: try!(d.read_struct_field("accounts", 1, |d| {
          d.read_seq(|d, len| {
            let mut ret = HashMap::new();
            for i in range(0, len) {
              let accnt: Account = try!(d.read_seq_elt(i, Decodable::decode));
              ret.insert(accnt.name.clone(), accnt);
            }
            Ok(ret)
          })
        }))
      })
    })
  }
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
  pub fn account_insert(&mut self, name: String)
                        -> Result<(), Error> {
    if self.accounts.find(&name).is_some() {
      return Err(DuplicateAccount);
    }

    let idx = self.accounts.len() as u32;
    self.accounts.insert(name.clone(), Account {
      name: name,
      internal_path: vec![Hardened(idx), Normal(1)],
      internal_used: vec![],
      internal_next: 0,
      external_path: vec![Hardened(idx), Normal(0)],
      external_used: vec![],
      external_next: 0
    });
    Ok(())
  }

  /// Locates an account in a wallet
  pub fn account_find<'a>(&'a self, name: &str)
                          -> Option<&'a Account> {
    self.accounts.find_equiv(&name)
  }

  /// Create a new address
  pub fn new_address(&mut self,
                     account: &str,
                     chain: AccountChain)
                     -> Result<Address, Error> {
    let (k1, k2) = self.siphash_key();
    // TODO: unnecessary allocation, waiting on *_equiv in stdlib
    let account = self.accounts.find_mut(&account.to_string());
    let account = match account { Some(a) => a, None => return Err(AccountNotFound) };

    let (mut i, master) = match chain {
      Internal => (account.internal_next,
                   try!(ExtendedPrivKey::from_path(
                          &self.master,
                          account.internal_path.as_slice()).map_err(Bip32Error))),
      External => (account.external_next,
                   try!(ExtendedPrivKey::from_path(
                          &self.master,
                          account.external_path.as_slice()).map_err(Bip32Error))),
    };

    // Scan for next admissible address
    let mut sk = try!(master.ckd_priv(Normal(i)).map_err(Bip32Error));
    let mut address = Address::from_key(
                        master.network,
                        &PublicKey::from_secret_key(&sk.secret_key, true));
    while !admissible_address(k1, k2, &address) {
      i += 1;
      sk = try!(master.ckd_priv(Normal(i)).map_err(Bip32Error));
      address = Address::from_key(
                  master.network,
                  &PublicKey::from_secret_key(&sk.secret_key, true));
    }

    match chain {
      Internal => {
        account.internal_used.push(Normal(i));
        account.internal_next = i + 1;
      }
      External => {
        account.external_used.push(Normal(i));
        account.external_next = i + 1;
      }
    }

    Ok(address)
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
      PayToPubkeyHash(addr) => admissible_address(k1, k2, &addr),
      _ => false
    }
  }
}

/// A filter used for creating a small address index. Note that this
/// function, `might_be_mine` and `siphash_key` are used by wizards-wallet
/// to create a cheap UTXO index
#[inline]
pub fn admissible_address(k1: u64, k2: u64, addr: &Address) -> bool {
  hash_with_keys(k1, k2, &addr.as_slice()) & 0xFF == 0
}

