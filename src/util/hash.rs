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

//! # Hash functions
//!
//! Utility functions related to hashing data, including merkleization

use collections::bitv::{Bitv, from_bytes};
use core::char::from_digit;
use core::cmp::min;
use std::default::Default;
use std::fmt;
use std::io::MemWriter;
use std::mem::transmute;
use std::hash::{Hash, Hasher};
use serialize::json::{mod, ToJson};

use crypto::digest::Digest;
use crypto::sha2;

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{RawEncoder, BitcoinHash, SimpleDecoder, SimpleEncoder};
use util::uint::Uint128;
use util::uint::Uint256;

/// A Bitcoin hash, 32-bytes, computed from x as SHA256(SHA256(x))
pub struct Sha256dHash([u8, ..32]);

/// A "hasher" which just truncates
pub struct DumbHasher;

// Allow these to be used as a key for Rust's HashMap et. al.
impl Hash<u64> for Sha256dHash {
  #[inline]
  fn hash(&self, state: &mut u64) {
    use std::mem;
    let myarr: [u64, ..4] = unsafe { mem::transmute(*self) };
    *state = myarr[0];
  }
}

impl Hash<u64> for Uint256 {
  #[inline]
  fn hash(&self, state: &mut u64) {
    use std::mem;
    let myarr: [u64, ..4] = unsafe { mem::transmute(*self) };
    *state = myarr[0];
  }
}

impl Hash<u64> for Uint128 {
  #[inline]
  fn hash(&self, state: &mut u64) {
    use std::mem;
    let myarr: [u64, ..2] = unsafe { mem::transmute(*self) };
    *state = myarr[0];
  }
}

impl Hasher<u64> for DumbHasher {
  #[inline]
  fn hash<T: Hash<u64>>(&self, value: &T) -> u64 {
    let mut ret = 0u64;
    value.hash(&mut ret);
    ret
  }
}

impl Default for DumbHasher {
  #[inline]
  fn default() -> DumbHasher { DumbHasher }
}

/// Returns the all-zeroes "hash"
pub fn zero_hash() -> Sha256dHash { Sha256dHash([0u8, ..32]) }

impl Sha256dHash {
  /// Create a hash by hashing some data
  pub fn from_data(data: &[u8]) -> Sha256dHash {
    let Sha256dHash(mut ret) = zero_hash();
    let mut sha2 = sha2::Sha256::new();
    sha2.input(data);
    sha2.result(ret.as_mut_slice());
    sha2.reset();
    sha2.input(ret.as_slice());
    sha2.result(ret.as_mut_slice());
    Sha256dHash(ret)
  }

  /// Returns a slice containing the bytes of the has
  pub fn as_slice<'a>(&'a self) -> &'a [u8] {
    let &Sha256dHash(ref data) = self;
    data.as_slice()
  }

  /// Converts a hash to a bit vector
  pub fn as_bitv(&self) -> Bitv {
    from_bytes(self.as_slice())
  }

  /// Converts a hash to a Uint256, interpreting it as a little endian number.
  pub fn into_uint256(self) -> Uint256 {
    let Sha256dHash(data) = self;
    unsafe { Uint256(transmute(data)) }
  }

  /// Converts a hash to a Uint128, interpreting it as a little endian number.
  pub fn into_uint128(self) -> Uint128 {
    let Sha256dHash(data) = self;
    // TODO: this function won't work correctly on big-endian machines
    unsafe { Uint128(transmute([data[16], data[17], data[18], data[19], data[20],
                                data[21], data[22], data[23], data[24], data[25],
                                data[26], data[27], data[28], data[29], data[30],
                                data[31]])) }
  }

  /// Human-readable hex output
  pub fn le_hex_string(&self) -> String {
    let &Sha256dHash(data) = self;
    let mut ret = String::with_capacity(64);
    for i in range(0u, 32).rev() {
      ret.push_char(from_digit((data[i] / 0x10) as uint, 16).unwrap());
      ret.push_char(from_digit((data[i] & 0x0f) as uint, 16).unwrap());
    }
    ret
  }

  /// Human-readable hex output
  pub fn be_hex_string(&self) -> String {
    let &Sha256dHash(data) = self;
    let mut ret = String::with_capacity(64);
    for i in range(0u, 32) {
      ret.push_char(from_digit((data[i] / 0x10) as uint, 16).unwrap());
      ret.push_char(from_digit((data[i] & 0x0f) as uint, 16).unwrap());
    }
    ret
  }
}

impl Clone for Sha256dHash {
  fn clone(&self) -> Sha256dHash {
    *self
  }
}

impl PartialEq for Sha256dHash {
  fn eq(&self, other: &Sha256dHash) -> bool {
    let &Sha256dHash(ref mydata) = self;
    let &Sha256dHash(ref yourdata) = other;
    for i in range(0u, 32) {
      if mydata[i] != yourdata[i] {
        return false;
      }
    }
    return true;
  }
}

impl Eq for Sha256dHash {}

impl Index<uint, u8> for Sha256dHash {
  #[inline]
  fn index<'a>(&'a self, idx: &uint) -> &'a u8 {
    let &Sha256dHash(ref data) = self;
    &data[*idx]
  }
}

// Note that this outputs hashes as big endian hex numbers, so this should be
// used only for user-facing stuff. Internal and network serialization is
// little-endian and should be done using the consensus `encodable::ConsensusEncodable`
// interface.
impl ToJson for Sha256dHash {
  fn to_json(&self) -> json::Json {
    json::String(self.be_hex_string())
  }
}

// Non-consensus encoding (big-endian hex string)
impl<S: ::serialize::Encoder<E>, E> ::serialize::Encodable<S, E> for Sha256dHash {
  #[inline]
  fn encode(&self, s: &mut S) -> Result<(), E> {
    s.emit_str(self.be_hex_string().as_slice())
  }
}

impl<D: ::serialize::Decoder<E>, E> ::serialize::Decodable<D, E> for Sha256dHash {
  #[inline]
  fn decode(d: &mut D) -> Result<Sha256dHash, E> {
    use serialize::hex::FromHex;

    let hex_str = try!(d.read_str());
    if hex_str.len() != 64 {
      d.error("incorrect hash length");
    }
    let raw_str = try!(hex_str.as_slice().from_hex()
                         .map_err(|_| d.error("non-hexadecimal hash string")));
    let mut ret = [0u8, ..32];
    for i in range(0, 32) {
      ret[i] = raw_str[i];
    }
    Ok(Sha256dHash(ret))
  }
}

// Consensus encoding (little-endian)
impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for Sha256dHash {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    self.into_uint256().consensus_encode(s)
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for Sha256dHash {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Sha256dHash, E> {
    Ok(Sha256dHash(try!(ConsensusDecodable::consensus_decode(d))))
  }
}

impl fmt::LowerHex for Sha256dHash {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let &Sha256dHash(ref data) = self;
    let mut rv = [0, ..64];
    let mut hex = data.iter().rev().map(|n| *n).enumerate();
    for (i, ch) in hex {
      rv[2*i]     = from_digit(ch as uint / 16, 16).unwrap() as u8;
      rv[2*i + 1] = from_digit(ch as uint % 16, 16).unwrap() as u8;
    }
    f.write(rv.as_slice())
  }
}

impl fmt::Show for Sha256dHash {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:x}", *self)
  }
}

/// Any collection of objects for which a merkle root makes sense to calculate
pub trait MerkleRoot {
  /// Construct a merkle tree from a collection, with elements ordered as
  /// they were in the original collection, and return the merkle root.
  fn merkle_root(&self) -> Sha256dHash;
}

impl<'a, T: BitcoinHash> MerkleRoot for &'a [T] {
  fn merkle_root(&self) -> Sha256dHash {
    fn merkle_root(data: Vec<Sha256dHash>) -> Sha256dHash {
      // Base case
      if data.len() < 1 {
        return zero_hash();
      }
      if data.len() < 2 {
        return data[0];
      }
      // Recursion
      let mut next = vec![];
      for idx in range(0, (data.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, data.len() - 1);
        let mut encoder = RawEncoder::new(MemWriter::new());
        data[idx1].consensus_encode(&mut encoder).unwrap();
        data[idx2].consensus_encode(&mut encoder).unwrap();
        next.push(encoder.unwrap().unwrap().bitcoin_hash());
      }
      merkle_root(next)
    }
    merkle_root(self.iter().map(|obj| obj.bitcoin_hash()).collect())
  }
}

impl <T: BitcoinHash> MerkleRoot for Vec<T> {
  fn merkle_root(&self) -> Sha256dHash {
    self.as_slice().merkle_root()
  }
}


#[cfg(test)]
mod tests {
  use std::prelude::*;
  use collections::bitv::from_bytes;
  use std::io::{MemWriter, MemReader, Reader, Writer};
  use std::str::from_utf8;

  use serialize::Encodable;
  use serialize::json;
  use util::hash::Sha256dHash;
  use util::misc::hex_bytes;

  #[test]
  fn test_sha256d() {
    assert_eq!(Sha256dHash::from_data(&[]).as_slice(),
               hex_bytes("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap().as_slice());
    assert_eq!(Sha256dHash::from_data(&[]).le_hex_string(),
               "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d".to_string());
    assert_eq!(Sha256dHash::from_data(b"TEST").as_slice(),
               hex_bytes("d7bd34bfe44a18d2aa755a344fe3e6b06ed0473772e6dfce16ac71ba0b0a241c").unwrap().as_slice());
  }

  #[test]
  fn test_hash_to_bitvset() {
    assert_eq!(Sha256dHash::from_data(&[]).as_bitv(),
               from_bytes(hex_bytes("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap().as_slice()));
  }

  #[test]
  fn test_hash_encode_decode() {
    let hash = Sha256dHash::from_data(&[]);
    let mut writer = MemWriter::new();
    {
      let mut encoder = json::Encoder::new(&mut writer);
      assert!(hash.encode(&mut encoder).is_ok());
    }
    let res = writer.unwrap();
    assert_eq!(res.as_slice(),
               "\"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456\"".as_bytes());
    assert_eq!(json::decode(from_utf8(res.as_slice()).unwrap()), Ok(hash));
  }
}

