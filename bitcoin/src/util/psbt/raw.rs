// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! Raw PSBT key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.
//!

use crate::prelude::*;
use core::fmt;
use core::convert::TryFrom;

use crate::io;
use crate::consensus::encode::{self, ReadExt, WriteExt, Decodable, Encodable, VarInt, serialize, deserialize, MAX_VEC_SIZE};
use crate::hashes::hex;
use crate::util::psbt::Error;
use crate::util::read_to_end;

/// A PSBT key in its raw byte form.
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u8,
    /// The key itself in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value of this key-value pair in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub value: Vec<u8>,
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u8;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ProprietaryKey<Subtype=ProprietaryType> where Subtype: Copy + From<u8> + Into<u8> {
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: ", self.type_value)?;
        hex::format_hex(&self.key[..], f)
    }
}

impl Decodable for Key {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let VarInt(byte_size): VarInt = Decodable::consensus_decode(r)?;

        if byte_size == 0 {
            return Err(Error::NoMorePairs.into());
        }

        let key_byte_size: u64 = byte_size - 1;

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(encode::Error::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            })
        }

        let type_value: u8 = Decodable::consensus_decode(r)?;

        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(r)?);
        }

        Ok(Key { type_value, key })
    }
}

impl Encodable for Key {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt((self.key.len() + 1) as u64).consensus_encode(w)?;

        len += self.type_value.consensus_encode(w)?;

        for key in &self.key {
            len += key.consensus_encode(w)?
        }

        Ok(len)
    }
}

impl Encodable for Pair {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.key.consensus_encode(w)?;
        Ok(len + self.value.consensus_encode(w)?)
    }
}

impl Decodable for Pair {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Pair {
            key: Decodable::consensus_decode(r)?,
            value: Decodable::consensus_decode(r)?,
        })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)? + 1;
        w.emit_u8(self.subtype.into())?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let subtype = Subtype::from(r.read_u8()?);
        let key = read_to_end(r)?;

        Ok(ProprietaryKey { prefix, subtype, key })
    }
}

impl<Subtype> ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    /// Constructs [ProprietaryKey] from [Key]; returns
    /// [Error::InvalidProprietaryKey] if `key` do not starts with 0xFC byte
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_key(key: Key) -> Result<Self, Error> {
        Self::try_from(key)
    }

    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key {
        Key {
            type_value: 0xFC,
            key: serialize(self)
        }
    }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype:Copy + From<u8> + Into<u8> {
    type Error = Error;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    /// Returns [`Error::InvalidProprietaryKey`] if `key` does not start with `0xFC` byte.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey)
        }

        Ok(deserialize(&key.key)?)
    }
}
