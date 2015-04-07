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
use serde::{Serialize, Deserialize, Serializer, Deserializer};

use secp256k1::key::PublicKey;

use byteorder::{ByteOrder, LittleEndian};
use blockdata::utxoset::UtxoSet;
use network::constants::Network;
use wallet::bip32::{self, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use wallet::bip32::ChildNumber::{Normal, Hardened};
use wallet::address::Address;
use wallet::address_index::AddressIndex;

/// A Wallet error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
  /// Tried to lookup an account by name, but none was found
  AccountNotFound,
  /// Tried to add an account when one already exists with that name
  DuplicateAccount,
  /// An error occured in a BIP32 derivation
  Bip32Error(bip32::Error),
  /// Tried to use a wallet without an address index
  NoAddressIndex
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Account {
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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
  master: ExtendedPrivKey,
  accounts: HashMap<String, Account>,
  index: Option<AddressIndex>
}

impl Serialize for Wallet {
  fn serialize<S>(&self, s: &mut S) -> Result<(), S::Error>
      where S: Serializer {
    let len = self.accounts.len();
    try!(self.master.serialize(s));
    self.accounts.serialize(s)
  }
}

impl Deserialize for Wallet {
  fn deserialize<D>(d: &mut D) -> Result<Wallet, D::Error>
      where D: Deserializer {
    Ok(Wallet {
      master: try!(Deserialize::deserialize(d)),
      accounts: try!(Deserialize::deserialize(d)),
      index: None
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
      accounts: accounts,
      index: None
    })
  }

  /// Creates the address index
  #[inline]
  pub fn build_index(&mut self, utxo_set: &UtxoSet) {
    let new = AddressIndex::new(utxo_set, self);
    self.index = Some(new);
  }

  /// Accessor for the wallet's address index
  #[inline]
  pub fn index<'a>(&'a self) -> Option<&'a AddressIndex> {
    self.index.as_ref()
  }

  /// Mutable accessor for the wallet's address index
  #[inline]
  pub fn index_mut<'a>(&'a mut self) -> Option<&'a mut AddressIndex> {
    self.index.as_mut()
  }

  /// Adds an account to a wallet
  pub fn account_insert(&mut self, name: String)
                        -> Result<(), Error> {
    if self.accounts.contains_key(&name) {
      return Err(Error::DuplicateAccount);
    }

    let idx = self.accounts.len() as u32;
    self.accounts.insert(name, Account {
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
  #[inline]
  pub fn account_get<'a>(&'a self, name: &str) -> Option<&'a Account> {
    self.accounts.get(name)
  }

  /// Create a new address
  pub fn new_address(&mut self,
                     account: &str,
                     chain: AccountChain)
                     -> Result<Address, Error> {
    let account = self.accounts.get_mut(account);
    let account = match account { Some(a) => a, None => return Err(Error::AccountNotFound) };
    let index = match self.index { Some(ref i) => i, None => return Err(Error::NoAddressIndex) };

    let (mut i, master) = match chain {
      Internal => (account.internal_next,
                   try!(ExtendedPrivKey::from_path(
                          &self.master,
                          account.internal_path.as_slice()).map_err(Error::Bip32Error))),
      External => (account.external_next,
                   try!(ExtendedPrivKey::from_path(
                          &self.master,
                          account.external_path.as_slice()).map_err(Error::Bip32Error))),
    };

    // Scan for next admissible address
    let mut sk = try!(master.ckd_priv(Normal(i)).map_err(Error::Bip32Error));
    let mut address = Address::from_key(
                        master.network,
                        &PublicKey::from_secret_key(&sk.secret_key, true));
    while !index.admissible_address(&address) {
      i += 1;
      sk = try!(master.ckd_priv(Normal(i)).map_err(Error::Bip32Error));
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
    (LittleEndian::read_u64(&self.master.chain_code[0..8]),
     LittleEndian::read_u64(&self.master.chain_code[8..16]))
  }

  /// Total balance
  pub fn total_balance(&self) -> Result<u64, Error> {
    let mut ret = 0;
    for (_, account) in self.accounts.iter() {
      ret += try!(self.account_balance(account));
    }
    Ok(ret)
  }

  /// Account balance
  pub fn balance(&self, account: &str) -> Result<u64, Error> {
    let account = self.accounts.get(account);
    let account = match account { Some(a) => a, None => return Err(Error::AccountNotFound) };
    self.account_balance(account)
  }

  fn account_balance(&self, account: &Account) -> Result<u64, Error> {
    let index = match self.index { Some(ref i) => i, None => return Err(Error::NoAddressIndex) };

    let mut ret = 0;

    // Sum internal balance
    let master = try!(ExtendedPrivKey::from_path(
                        &self.master,
                        account.internal_path.as_slice()).map_err(Error::Bip32Error));
    for &cnum in account.internal_used.iter() {
      let sk = try!(master.ckd_priv(cnum).map_err(Error::Bip32Error));
      let pk = ExtendedPubKey::from_private(&sk);
      let addr = Address::from_key(pk.network, &pk.public_key);
      for out in index.find_by_script(&addr.script_pubkey()).iter() {
        ret += out.txo.value;
      }
    }
    // Sum external balance
    let master = try!(ExtendedPrivKey::from_path(
                        &self.master,
                        account.external_path.as_slice()).map_err(Error::Bip32Error));
    for &cnum in account.external_used.iter() {
      let sk = try!(master.ckd_priv(cnum).map_err(Error::Bip32Error));
      let pk = ExtendedPubKey::from_private(&sk);
      let addr = Address::from_key(pk.network, &pk.public_key);
      for out in index.find_by_script(&addr.script_pubkey()).iter() {
        ret += out.txo.value;
      }
    }

    Ok(ret)
  }
}

