// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! Raw PSBT key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::ToU64 as _;
use io::{BufRead, Write};

use super::serialize::{Deserialize, Serialize};
use crate::consensus::encode::{
    self, deserialize, serialize, Decodable, Encodable, ReadExt, WriteExt, MAX_VEC_SIZE,
};
use crate::prelude::{DisplayHex, Vec};
use crate::psbt::Error;

/// A PSBT key in its raw byte form.
///
/// `<key> := <keylen> <keytype> <keydata>`
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u64, // Encoded as a compact size.
    /// The key data itself in raw byte form.
    pub key_data: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
/// `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value data of this key-value pair in raw byte form.
    /// `<value> := <valuelen> <valuedata>`
    pub value: Vec<u8>,
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u64;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    pub key: Vec<u8>,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key_data.as_hex())
    }
}

impl Key {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let byte_size = r.read_compact_size()?;

        if byte_size == 0 {
            return Err(Error::NoMorePairs);
        }

        let key_byte_size: u64 = byte_size - 1;

        if key_byte_size > MAX_VEC_SIZE.to_u64() {
            return Err(encode::Error::Parse(encode::ParseError::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            })
            .into());
        }

        let type_value = r.read_compact_size()?;

        let mut key_data = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key_data.push(Decodable::consensus_decode(r)?);
        }

        Ok(Self { type_value, key_data })
    }
}

impl Serialize for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.emit_compact_size(self.key_data.len() + 1).expect("in-memory writers don't error");

        buf.emit_compact_size(self.type_value).expect("in-memory writers don't error");

        for key in &self.key_data {
            key.consensus_encode(&mut buf).expect("in-memory writers don't error");
        }

        buf
    }
}

impl Serialize for Pair {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.key.serialize());
        // <value> := <valuelen> <valuedata>
        self.value.consensus_encode(&mut buf).unwrap();
        buf
    }
}

impl Deserialize for Pair {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = bytes;
        Self::decode(&mut decoder)
    }
}

impl Pair {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        len += w.emit_compact_size(self.subtype.into())?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let subtype = Subtype::from(r.read_compact_size()?);

        // The limit is a DOS protection mechanism the exact value is not
        // important, 1024 bytes is bigger than any key should be.
        let mut key = vec![];
        let _ = io::Read::read_to_limit(r, &mut key, 1024)?;

        Ok(Self { prefix, subtype, key })
    }
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Constructs a new full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key { Key { type_value: 0xFC, key_data: serialize(self) } }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Error = Error;

    /// Constructs a new [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProprietaryKey`] if `key` does not start with `0xFC` byte.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key_data)?)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ProprietaryKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            prefix: Vec::<u8>::arbitrary(u)?,
            subtype: u64::arbitrary(u)?,
            key: Vec::<u8>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Key {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { type_value: u.arbitrary()?, key_data: Vec::<u8>::arbitrary(u)? })
    }
}
