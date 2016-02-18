// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

use std::char::from_digit;
use std::cmp::min;
use std::default::Default;
use std::error;
use std::fmt::{self, Write};
use std::io::Cursor;
use std::mem;
use serde;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;

use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{RawEncoder, BitcoinHash};
use util::uint::Uint256;

/// Hex deserialization error
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HexError {
    /// Length was not 64 characters
    BadLength(usize),
    /// Non-hex character in string
    BadCharacter(char)
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HexError::BadLength(n) => write!(f, "bad length {} for sha256d hex string", n),
            HexError::BadCharacter(c) => write!(f, "bad character {} in sha256d hex string", c)
        }
    }
}

impl error::Error for HexError {
    fn cause(&self) -> Option<&error::Error> { None }
    fn description(&self) -> &str {
        match *self {
            HexError::BadLength(_) => "sha256d hex string non-64 length",
            HexError::BadCharacter(_) => "sha256d bad hex character"
        }
    }
}

/// A Bitcoin hash, 32-bytes, computed from x as SHA256(SHA256(x))
pub struct Sha256dHash([u8; 32]);
impl_array_newtype!(Sha256dHash, u8, 32);

/// A RIPEMD-160 hash
pub struct Ripemd160Hash([u8; 20]);
impl_array_newtype!(Ripemd160Hash, u8, 20);

/// A Bitcoin hash160, 20-bytes, computed from x as RIPEMD160(SHA256(x))
pub struct Hash160([u8; 20]);
impl_array_newtype!(Hash160, u8, 20);

/// A 32-bit hash obtained by truncating a real hash
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Hash32((u8, u8, u8, u8));

/// A 48-bit hash obtained by truncating a real hash
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Hash48((u8, u8, u8, u8, u8, u8));

/// A 64-bit hash obtained by truncating a real hash
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Hash64((u8, u8, u8, u8, u8, u8, u8, u8));

impl Ripemd160Hash {
    /// Create a hash by hashing some data
    pub fn from_data(data: &[u8]) -> Ripemd160Hash {
        let mut ret = [0; 20];
        let mut rmd = Ripemd160::new();
        rmd.input(data);
        rmd.result(&mut ret);
        Ripemd160Hash(ret)
    }
}

impl Hash160 {
    /// Create a hash by hashing some data
    pub fn from_data(data: &[u8]) -> Hash160 {
        let mut tmp = [0; 32];
        let mut ret = [0; 20];
        let mut sha2 = Sha256::new();
        let mut rmd = Ripemd160::new();
        sha2.input(data);
        sha2.result(&mut tmp);
        rmd.input(&tmp);
        rmd.result(&mut ret);
        Hash160(ret)
    }
}

// This doesn't make much sense to me, but is implicit behaviour
// in the C++ reference client, so we need it for consensus.
impl Default for Sha256dHash {
    #[inline]
    fn default() -> Sha256dHash { Sha256dHash([0u8; 32]) }
}

impl Sha256dHash {
    /// Create a hash by hashing some data
    pub fn from_data(data: &[u8]) -> Sha256dHash {
        let Sha256dHash(mut ret): Sha256dHash = Default::default();
        let mut sha2 = Sha256::new();
        sha2.input(data);
        sha2.result(&mut ret);
        sha2.reset();
        sha2.input(&ret);
        sha2.result(&mut ret);
        Sha256dHash(ret)
    }

    /// Converts a hash to a little-endian Uint256
    #[inline]
    pub fn into_le(self) -> Uint256 {
        let Sha256dHash(data) = self;
        let mut ret: [u64; 4] = unsafe { mem::transmute(data) };
        for x in (&mut ret).iter_mut() { *x = x.to_le(); }
        Uint256(ret)
    }

    /// Converts a hash to a big-endian Uint256
    #[inline]
    pub fn into_be(self) -> Uint256 {
        let Sha256dHash(mut data) = self;
        data.reverse();
        let mut ret: [u64; 4] = unsafe { mem::transmute(data) };
        for x in (&mut ret).iter_mut() { *x = x.to_be(); }
        Uint256(ret)
    }

    /// Converts a hash to a Hash32 by truncation
    #[inline]
    pub fn into_hash32(self) -> Hash32 {
        let Sha256dHash(data) = self;
        unsafe { mem::transmute([data[0], data[8], data[16], data[24]]) }
    }

    /// Converts a hash to a Hash48 by truncation
    #[inline]
    pub fn into_hash48(self) -> Hash48 {
        let Sha256dHash(data) = self;
        unsafe { mem::transmute([data[0], data[6], data[12], data[18], data[24], data[30]]) }
    }

    // Human-readable hex output

    /// Decodes a big-endian (i.e. reversed vs sha256sum output) hex string as a Sha256dHash
    #[inline]
    pub fn from_hex(s: &str) -> Result<Sha256dHash, HexError> {
        if s.len() != 64 {
            return Err(HexError::BadLength(s.len()));
        }

        let bytes = s.as_bytes();
        let mut ret: [u8; 32] = unsafe { mem::uninitialized() };
        for i in 0..32 {
           let hi = match bytes[2*i] {
               b @ b'0'...b'9' => (b - b'0') as u8,
               b @ b'a'...b'f' => (b - b'a' + 10) as u8,
               b @ b'A'...b'F' => (b - b'A' + 10) as u8,
               b => return Err(HexError::BadCharacter(b as char))
           };
           let lo = match bytes[2*i + 1] {
               b @ b'0'...b'9' => (b - b'0') as u8,
               b @ b'a'...b'f' => (b - b'a' + 10) as u8,
               b @ b'A'...b'F' => (b - b'A' + 10) as u8,
               b => return Err(HexError::BadCharacter(b as char))
           };
           ret[31 - i] = hi * 0x10 + lo;
        }
        Ok(Sha256dHash(ret))
    }

    /// Converts a hash to a Hash64 by truncation
    #[inline]
    pub fn into_hash64(self) -> Hash64 {
        let Sha256dHash(data) = self;
        unsafe { mem::transmute([data[0], data[4], data[8], data[12],
                            data[16], data[20], data[24], data[28]]) }
    }

    /// Human-readable hex output
    pub fn le_hex_string(&self) -> String {
        let &Sha256dHash(data) = self;
        let mut ret = String::with_capacity(64);
        for item in data.iter().take(32) {
            ret.push(from_digit((*item / 0x10) as u32, 16).unwrap());
            ret.push(from_digit((*item & 0x0f) as u32, 16).unwrap());
        }
        ret
    }

    /// Human-readable hex output
    pub fn be_hex_string(&self) -> String {
        let &Sha256dHash(data) = self;
        let mut ret = String::with_capacity(64);
        for i in (0..32).rev() {
            ret.push(from_digit((data[i] / 0x10) as u32, 16).unwrap());
            ret.push(from_digit((data[i] & 0x0f) as u32, 16).unwrap());
        }
        ret
    }
}

// Note that this outputs hashes as big endian hex numbers, so this should be
// used only for user-facing stuff. Internal and network serialization is
// little-endian and should be done using the consensus `encodable::ConsensusEncodable`
// interface.
impl serde::Serialize for Sha256dHash {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
            where S: serde::Serializer,
    {
        serializer.visit_str(&self.be_hex_string())
    }
}

impl serde::Deserialize for Sha256dHash {
    #[inline]
    fn deserialize<D>(d: &mut D) -> Result<Sha256dHash, D::Error>
        where D: serde::Deserializer
    {
        use serialize::hex::FromHex;

        struct Sha256dHashVisitor;
        impl serde::de::Visitor for Sha256dHashVisitor {
            type Value = Sha256dHash;

            fn visit_string<E>(&mut self, v: String) -> Result<Sha256dHash, E>
                where E: serde::de::Error
            {
                self.visit_str(&v)
            }

            fn visit_str<E>(&mut self, hex_str: &str) -> Result<Sha256dHash, E>
                where E: serde::de::Error
            {
                Sha256dHash::from_hex(hex_str).map_err(|e| serde::de::Error::syntax(&e.to_string()))
            }
        }

        d.visit(Sha256dHashVisitor)
    }
}

// Consensus encoding (little-endian)
impl_newtype_consensus_encoding!(Hash32);
impl_newtype_consensus_encoding!(Hash48);
impl_newtype_consensus_encoding!(Hash64);
impl_newtype_consensus_encoding!(Sha256dHash);

impl fmt::Debug for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::Display for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::LowerHex for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            try!(write!(f, "{:02x}", ch));
        }
        Ok(())
    }
}

impl fmt::UpperHex for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            try!(write!(f, "{:02X}", ch));
        }
        Ok(())
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
                return Default::default();
            }
            if data.len() < 2 {
                return data[0];
            }
            // Recursion
            let mut next = vec![];
            for idx in 0..((data.len() + 1) / 2) {
                let idx1 = 2 * idx;
                let idx2 = min(idx1 + 1, data.len() - 1);
                let mut encoder = RawEncoder::new(Cursor::new(vec![]));
                data[idx1].consensus_encode(&mut encoder).unwrap();
                data[idx2].consensus_encode(&mut encoder).unwrap();
                next.push(encoder.into_inner().into_inner().bitcoin_hash());
            }
            merkle_root(next)
        }
        merkle_root(self.iter().map(|obj| obj.bitcoin_hash()).collect())
    }
}

impl <T: BitcoinHash> MerkleRoot for Vec<T> {
    fn merkle_root(&self) -> Sha256dHash {
        (&self[..]).merkle_root()
    }
}


#[cfg(test)]
mod tests {
    use num::FromPrimitive;
    use strason;

    use network::serialize::{serialize, deserialize};
    use util::hash::Sha256dHash;

    #[test]
    fn test_sha256d() {
        // nb the 5df6... output is the one you get from sha256sum. this is the
        // "little-endian" hex string since it matches the in-memory representation
        // of a Uint256 (which is little-endian) after transmutation
        assert_eq!(Sha256dHash::from_data(&[]).le_hex_string(),
                   "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
        assert_eq!(Sha256dHash::from_data(&[]).be_hex_string(),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");

        assert_eq!(format!("{}", Sha256dHash::from_data(&[])),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
        assert_eq!(format!("{:?}", Sha256dHash::from_data(&[])),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
        assert_eq!(format!("{:x}", Sha256dHash::from_data(&[])),
                   "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
        assert_eq!(format!("{:X}", Sha256dHash::from_data(&[])),
                   "56944C5D3F98413EF45CF54545538103CC9F298E0575820AD3591376E2E0F65D");
    }

    #[test]
    fn test_consenus_encode_roundtrip() {
        let hash = Sha256dHash::from_data(&[]);
        let serial = serialize(&hash).unwrap();
        let deserial = deserialize(&serial).unwrap();
        assert_eq!(hash, deserial);
    }

    #[test]
    fn test_hash_encode_decode() {
        let hash = Sha256dHash::from_data(&[]);
        let encoded = strason::from_serialize(&hash).unwrap();
        assert_eq!(encoded.to_bytes(),
                   "\"56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d\"".as_bytes());
        let decoded = encoded.into_deserialize().unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn test_sighash_single_vec() {
        let one = Sha256dHash([1, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Some(one.into_le()), FromPrimitive::from_u64(1));
        assert_eq!(Some(one.into_le().low_128()), FromPrimitive::from_u64(1));
    }
}

