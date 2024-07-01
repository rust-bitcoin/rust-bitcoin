// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! Raw PSBT key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.

use core::fmt;

use io::{BufRead, Write};

use super::serialize::{Deserialize, Serialize};
use crate::consensus::encode::{
    self, deserialize, serialize, Decodable, Encodable, ReadExt, VarInt, WriteExt, MAX_VEC_SIZE,
};
use crate::prelude::{DisplayHex, Vec};
use crate::psbt::Error;

/// A PSBT key in its raw byte form.
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u64,
    /// The key itself in raw byte form.
    /// `<key> := <keylen> <keytype> <keydata>`
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
/// `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value data of this key-value pair in raw byte form.
    /// `<value> := <valuelen> <valuedata>`
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
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
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
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key.as_hex())
    }
}

impl Key {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let VarInt(key_len): VarInt = Decodable::consensus_decode(r)?;

        if key_len == 0 {
            return Err(Error::NoMorePairs);
        }

        let key_type: VarInt = Decodable::consensus_decode(r)?;

        let key_byte_size: u64 = key_len - key_type.size() as u64;

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(encode::Error::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            }
            .into());
        }

        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(r)?);
        }

        Ok(Key { type_value: key_type.0, key })
    }
}

impl Serialize for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // `<key> := <keylen> <keytype> <keydata>`
        let key_type = VarInt(self.type_value);
        let key_len = VarInt((key_type.size() + self.key.len()) as u64); // Cast ok until 128 bit architectures exist.
        let key_data = &self.key;

        key_len.consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        key_type.consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        for b in key_data {
            b.consensus_encode(&mut buf).expect("in-memory writers don't error");
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
        Pair::decode(&mut decoder)
    }
}

impl Pair {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Pair { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)? + 1;
        w.emit_u8(self.subtype.into())?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let subtype = Subtype::from(r.read_u8()?);

        // The limit is a DOS protection mechanism the exact value is not
        // important, 1024 bytes is bigger than any key should be.
        let mut key = vec![];
        let _ = r.read_to_limit(&mut key, 1024)?;

        Ok(ProprietaryKey { prefix, subtype, key })
    }
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key { Key { type_value: 0xFC, key: serialize(self) } }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    type Error = Error;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProprietaryKey`] if `key` does not start with `0xFC` byte.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_key_byte_size_type_vaule_is_minimal() {
        let key = Key { type_value: 0x0fu64, key: vec![3, 4] };

        let got = key.serialize();
        let want = vec![0x03, 0x0f, 0x03, 0x04]; // <keylen>, <keytype>, <key>
        assert_eq!(got, want);
    }
}
