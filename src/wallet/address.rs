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

//! # Addresses
//!
//! Support for ordinary base58 Bitcoin addresses
//!

use secp256k1::key::PublicKey;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use blockdata::script::Script;
use blockdata::opcodes::all;
use network::constants::{Network, Bitcoin, BitcoinTestnet};
use util::hash::Ripemd160Hash;
use util::base58::{Base58Error,
                   InvalidLength, InvalidVersion,
                   FromBase58, ToBase58};

#[deriving(Clone, PartialEq, Eq)]
/// A Bitcoin address
pub struct Address {
  network: Network,
  hash: Ripemd160Hash
}

impl Address {
  /// Creates an address the raw 20 bytes of a hash
  #[inline]
  pub fn from_slice(network: Network, data: &[u8]) -> Address {
    Address {
      network: network,
      hash: Ripemd160Hash::from_slice(data)
    }
  }

  /// Returns a byteslice view of the `Address` --- note that no network information
  /// is contained in this.
  #[inline]
  pub fn as_slice<'a>(&'a self) -> &'a [u8] {
    self.hash.as_slice()
  }

  /// Creates an address from a public key
  #[inline]
  pub fn from_key(network: Network, pk: &PublicKey) -> Address {
    let mut sha = Sha256::new();
    let mut out = [0, ..32];
    sha.input(pk.as_slice());
    sha.result(out.as_mut_slice());
    Address {
      network: network,
      hash: Ripemd160Hash::from_data(out)
    }
  }

  /// Generates a script pubkey spending to this address
  #[inline]
  pub fn script_pubkey(&self) -> Script {
    let mut script = Script::new();
    script.push_opcode(all::OP_DUP);
    script.push_opcode(all::OP_HASH160);
    script.push_slice(self.hash.as_slice());
    script.push_opcode(all::OP_EQUALVERIFY);
    script.push_opcode(all::OP_CHECKSIG);
    script
  }
}

impl ToBase58 for Address {
  fn base58_layout(&self) -> Vec<u8> {
    let mut ret = vec![
      match self.network {
        Bitcoin => 0,
        BitcoinTestnet => 111
      }
    ];
    ret.push_all(self.hash.as_slice());
    ret
  }
}

impl FromBase58 for Address {
  fn from_base58_layout(data: Vec<u8>) -> Result<Address, Base58Error> {
    if data.len() != 21 {
      return Err(InvalidLength(data.len()));
    }

    Ok(Address {
      network: match data[0] {
        0   => Bitcoin,
        111 => BitcoinTestnet,
        x   => { return Err(InvalidVersion(vec![x])); }
      },
      hash: Ripemd160Hash::from_slice(data.slice_from(1))
    })
  }
}

impl ::std::fmt::Show for Address {
  fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
    write!(f, "{}", self.to_base58check())
  }
}

#[cfg(test)]
mod tests {
  use serialize::hex::FromHex;
  use test::{Bencher, black_box};

  use secp256k1::Secp256k1;

  use network::constants::Bitcoin;
  use util::hash::Ripemd160Hash;
  use util::base58::{FromBase58, ToBase58};
  use super::Address;

  #[test]
  fn test_address_58() {
    let addr = Address {
      network: Bitcoin,
      hash: Ripemd160Hash::from_slice("162c5ea71c0b23f5b9022ef047c4a86470a5b070".from_hex().unwrap().as_slice())
    };

    assert_eq!(addr.to_base58check().as_slice(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
    assert_eq!(FromBase58::from_base58check("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM"), Ok(addr));
  }

  #[bench]
  pub fn generate_address(bh: &mut Bencher) {
    let mut s = Secp256k1::new().unwrap();
    bh.iter( || {
      let (sk, pk) = s.generate_keypair(true);
      black_box(sk);
      black_box(pk);
      let addr = Address::from_key(Bitcoin, &pk);
      black_box(addr);
    });
  }

  #[bench]
  pub fn generate_uncompressed_address(bh: &mut Bencher) {
    let mut s = Secp256k1::new().unwrap();
    bh.iter( || {
      let (sk, pk) = s.generate_keypair(false);
      black_box(sk);
      black_box(pk);
      let addr = Address::from_key(Bitcoin, &pk);
      black_box(addr);
    });
  }

  #[bench]
  pub fn generate_sequential_address(bh: &mut Bencher) {
    let mut s = Secp256k1::new().unwrap();
    let (sk, _) = s.generate_keypair(true);
    let mut iter = sk.sequence(true);
    bh.iter( || {
      let (sk, pk) = iter.next().unwrap();
      black_box(sk);
      let addr = Address::from_key(Bitcoin, &pk);
      black_box(addr);
    });
  }
}

