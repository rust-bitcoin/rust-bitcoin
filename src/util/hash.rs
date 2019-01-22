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

//! Hash functions
//!
//! Utility functions related to hashing data, including merkleization

use std::char::from_digit;
use std::cmp::min;
use std::default::Default;
use std::error;
use std::fmt;
use std::io::{self, Write};
use std::mem;
#[cfg(feature = "serde")] use serde;

use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;

use consensus::encode::{Encodable, Decodable};
use util::uint::Uint256;

#[cfg(feature="fuzztarget")]      use fuzz_util::sha2::Sha256;
#[cfg(not(feature="fuzztarget"))] use crypto::sha2::Sha256;
use std::str::FromStr;

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

/// An object that allows serializing data into a sha256d
pub struct Sha256dEncoder(Sha256);

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

impl Sha256dEncoder {
    /// Create a new encoder
    pub fn new() -> Sha256dEncoder {
        Sha256dEncoder(Sha256::new())
    }

    /// Extract the hash from an encoder
    pub fn into_hash(mut self) -> Sha256dHash {
        let mut second_sha = Sha256::new();
        let mut tmp = [0; 32];
        self.0.result(&mut tmp);
        second_sha.input(&tmp);
        second_sha.result(&mut tmp);
        Sha256dHash(tmp)
    }
}

impl Write for Sha256dEncoder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
        let mut ret = [0; 32];
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

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Sha256dHash {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Sha256dHash;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a SHA256d hash")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Sha256dHash::from_hex(v).map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }
            
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Sha256dHash {
    /// Serialize a `Sha256dHash`.
    ///
    /// Note that this outputs hashes as big endian hex numbers, so this should be
    /// used only for user-facing stuff. Internal and network serialization is
    /// little-endian and should be done using the consensus
    /// [`Encodable`][1] interface.
    ///
    /// [1]: ../../network/encodable/trait.Encodable.html
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use std::{char, str};

        let mut string = [0; 64];
        for i in 0..32 {
            string[2 * i] = char::from_digit((self.0[31 - i] / 0x10) as u32, 16).unwrap() as u8;
            string[2 * i + 1] = char::from_digit((self.0[31 - i] & 0x0f) as u32, 16).unwrap() as u8;
        }

        let hex_str = unsafe { str::from_utf8_unchecked(&string) };
        serializer.serialize_str(hex_str)
    }
}

// Debug encodings
impl fmt::Debug for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Debug for Hash160 {
    /// Output the raw hash160 hash, not reversing it (nothing reverses the output of ripemd160 in Bitcoin)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Hash160(data) = self;
        for ch in data.iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

// Consensus encoding (no reversing)
impl_newtype_consensus_encoding!(Hash32);
impl_newtype_consensus_encoding!(Hash48);
impl_newtype_consensus_encoding!(Hash64);
impl_newtype_consensus_encoding!(Sha256dHash);

// User RPC/display encoding (reversed)
impl fmt::Display for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::LowerHex for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Sha256dHash {
    /// Output the sha256d hash in reverse, copying Bitcoin Core's behaviour
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &Sha256dHash(data) = self;
        for ch in data.iter().rev() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}

impl FromStr for Sha256dHash {
    type Err = HexError;

    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        Sha256dHash::from_hex(s)
    }
}

/// Any collection of objects for which a merkle root makes sense to calculate
pub trait MerkleRoot {
    /// Construct a merkle tree from a collection, with elements ordered as
    /// they were in the original collection, and return the merkle root.
    fn merkle_root(&self) -> Sha256dHash;
}

/// Calculates the merkle root of a list of txids hashes directly
pub fn bitcoin_merkle_root(data: Vec<Sha256dHash>) -> Sha256dHash {
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
        let mut encoder = Sha256dEncoder::new();
        data[idx1].consensus_encode(&mut encoder).unwrap();
        data[idx2].consensus_encode(&mut encoder).unwrap();
        next.push(encoder.into_hash());
    }
    bitcoin_merkle_root(next)
}

impl<'a, T: BitcoinHash> MerkleRoot for &'a [T] {
    fn merkle_root(&self) -> Sha256dHash {
        bitcoin_merkle_root(self.iter().map(|obj| obj.bitcoin_hash()).collect())
    }
}

impl <T: BitcoinHash> MerkleRoot for Vec<T> {
    fn merkle_root(&self) -> Sha256dHash {
        (&self[..]).merkle_root()
    }
}

/// Objects which are referred to by hash
pub trait BitcoinHash {
    /// Produces a Sha256dHash which can be used to refer to the object
    fn bitcoin_hash(&self) -> Sha256dHash;
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "serde", feature = "strason"))]
    use strason::Json;

    use consensus::encode::{Encodable, VarInt};
    use consensus::encode::{serialize, deserialize};
    use util::uint::{Uint128, Uint256};
    use super::*;

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
    fn sha256d_from_str_parses_from_human_readable_hex() {

        let human_readable_hex_tx_id = "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d";

        let from_hex = Sha256dHash::from_hex(human_readable_hex_tx_id).unwrap();
        let from_str = human_readable_hex_tx_id.parse().unwrap();

        assert_eq!(from_hex, from_str)
    }

    #[test]
    fn test_sha256d_data() {
        assert_eq!(
            Sha256dHash::from_data(&[]).as_bytes(),
            &[
                0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
                0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
                0x5d, 0x4c, 0x94, 0x56,
            ]
        );
    }

    #[test]
    fn sha256d_encoder() {
        let test = vec![true, false, true, true, false];
        let mut enc = Sha256dEncoder::new();
        assert!(test.consensus_encode(&mut enc).is_ok());
        assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test)));

        macro_rules! array_encode_test (
            ($ty:ty) => ({
                // try serializing the whole array
                let test: [$ty; 1000] = [1; 1000];
                let mut enc = Sha256dEncoder::new();
                assert!((&test[..]).consensus_encode(&mut enc).is_ok());
                assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test[..])));

                // try doing it just one object at a time
                let mut enc = Sha256dEncoder::new();
                assert!(VarInt(test.len() as u64).consensus_encode(&mut enc).is_ok());
                for obj in &test[..] {
                    assert!(obj.consensus_encode(&mut enc).is_ok());
                }
                assert_eq!(enc.into_hash(), Sha256dHash::from_data(&serialize(&test[..])));
            })
        );

        array_encode_test!(u64);
        array_encode_test!(u32);
        array_encode_test!(u16);
        array_encode_test!(u8);
        array_encode_test!(i64);
        array_encode_test!(i32);
        array_encode_test!(i16);
        array_encode_test!(i8);
    }

    #[test]
    fn test_consenus_encode_roundtrip() {
        let hash = Sha256dHash::from_data(&[]);
        let serial = serialize(&hash);
        let deserial = deserialize(&serial).unwrap();
        assert_eq!(hash, deserial);
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "strason"))]
    fn test_hash_encode_decode() {
        let hash = Sha256dHash::from_data(&[]);
        let encoded = Json::from_serialize(&hash).unwrap();
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
        assert_eq!(Some(one.into_le()), Uint256::from_u64(1));
        assert_eq!(Some(one.into_le().low_128()), Uint128::from_u64(1));
    }
}

