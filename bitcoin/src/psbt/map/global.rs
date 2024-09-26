// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use internals::{write_err, ToU64 as _};
use io::{BufRead, Cursor, Read};

use crate::bip32::{self, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use crate::consensus::encode::MAX_VEC_SIZE;
use crate::consensus::{encode, Decodable};
use crate::prelude::{btree_map, BTreeMap, Vec};
use crate::psbt::consts::{
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
};
use crate::psbt::map::Map;
use crate::psbt::{raw, serialize};
use crate::transaction::Transaction;

/// The global key-value map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Global {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpub: BTreeMap<Xpub, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Global {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let mut r = r.take(MAX_VEC_SIZE.to_u64());
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknown: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        // Use a closure so we can insert pair into one of the mutable local variables above.
        let mut insert_pair = |pair: raw::Pair| {
            match pair.key.type_value {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    // key has to be empty
                    if pair.key.key_data.is_empty() {
                        // there can only be one unsigned transaction
                        if tx.is_none() {
                            let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);

                            // Manually deserialized to ensure 0-input
                            // txs without witnesses are deserialized
                            // properly.
                            tx = Some(Transaction {
                                version: Decodable::consensus_decode(&mut decoder)?,
                                input: Decodable::consensus_decode(&mut decoder)?,
                                output: Decodable::consensus_decode(&mut decoder)?,
                                lock_time: Decodable::consensus_decode(&mut decoder)?,
                            });

                            if decoder.position() != vlen.to_u64() {
                                return Err(InsertPairError::PartialDataConsumption);
                            }
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    }
                }
                PSBT_GLOBAL_XPUB => {
                    if !pair.key.key_data.is_empty() {
                        let xpub = Xpub::decode(&pair.key.key_data)?;
                        if pair.value.is_empty() {
                            // TODO: keypair value is empty, consider adding a better error type.
                            return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                        }
                        if pair.value.len() < 4 {
                            // TODO: Add better error here.
                            return Err(InsertPairError::XpubInvalidFingerprint);
                        }
                        // TODO: Can we restrict the value further?
                        if pair.value.len() % 4 != 0 {
                            return Err(InsertPairError::XpubInvalidPath(pair.value.len()));
                        }
                        let child_count = pair.value.len() / 4 - 1;
                        let mut decoder = Cursor::new(pair.value);
                        let mut fingerprint = [0u8; 4];
                        decoder
                            .read_exact(&mut fingerprint[..])
                            .expect("in-memory readers don't err");
                        let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                        while let Ok(index) = u32::consensus_decode(&mut decoder) {
                            path.push(ChildNumber::from(index))
                        }
                        let derivation = DerivationPath::from(path);
                        // Keys, according to BIP-174, must be unique
                        if let Some(key_source) =
                            xpubs.insert(xpub, (Fingerprint::from(fingerprint), derivation))
                        {
                            return Err(InsertPairError::DuplicateXpub(key_source));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    }
                }
                PSBT_GLOBAL_VERSION => {
                    if pair.key.key_data.is_empty() {
                        if version.is_none() {
                            let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            if vlen != 4 {
                                return Err::<(), InsertPairError>(
                                    InsertPairError::ValueWrongLength(vlen, 4),
                                );
                            }
                            version = Some(Decodable::consensus_decode(&mut decoder)?);
                            // We only understand version 0 PSBTs. According to BIP-174 we
                            // should throw an error if we see anything other than version 0.
                            if version != Some(0) {
                                return Err(InsertPairError::WrongVersion(version.unwrap()));
                            }
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    }
                }
                // TODO: Remove clone by implementing TryFrom for reference.
                PSBT_GLOBAL_PROPRIETARY =>
                    if !pair.key.key_data.is_empty() {
                        match proprietary.entry(
                            raw::ProprietaryKey::try_from(pair.key.clone())
                                .map_err(|_| InsertPairError::InvalidProprietaryKey)?,
                        ) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(InsertPairError::DuplicateKey(pair.key)),
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    },
                _ => match unknown.entry(pair.key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(pair.value);
                    }
                    btree_map::Entry::Occupied(k) =>
                        return Err(InsertPairError::DuplicateKey(k.key().clone())),
                },
            }
            Ok(())
        };

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        let version = version.unwrap_or(0);

        if tx.is_none() {
            return Err(DecodeError::MissingUnsignedTx);
        }

        Ok(Global { unsigned_tx: tx.unwrap(), version, xpub: xpubs, proprietary, unknown })
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    pub(crate) fn unsigned_tx_checks(&self) -> Result<(), UnsignedTxError> {
        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(UnsignedTxError::HasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(UnsignedTxError::HasScriptWitnesses);
            }
        }

        Ok(())
    }
}

/// Ways that a Partially Signed Transaction might fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum UnsignedTxError {
    /// The scriptSigs for the unsigned transaction must be empty.
    HasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    HasScriptWitnesses,
}

impl fmt::Display for UnsignedTxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use UnsignedTxError::*;

        match *self {
            HasScriptSigs => f.write_str("the unsigned transaction has script sigs"),
            HasScriptWitnesses => f.write_str("the unsigned transaction has script witnesses"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsignedTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use UnsignedTxError::*;

        match *self {
            HasScriptSigs | HasScriptWitnesses => None,
        }
    }
}

impl Map for Global {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_UNSIGNED_TX, key_data: vec![] },
            value: {
                // Manually serialized to ensure 0-input txs are serialized
                // without witnesses.
                let mut ret = Vec::new();
                ret.extend(encode::serialize(&self.unsigned_tx.version));
                ret.extend(encode::serialize(&self.unsigned_tx.input));
                ret.extend(encode::serialize(&self.unsigned_tx.output));
                ret.extend(encode::serialize(&self.unsigned_tx.lock_time));
                ret
            },
        });

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key_data: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }

        // Serializing version only for non-default value; otherwise test vectors fail
        if self.version > 0 {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key_data: vec![] },
                value: self.version.to_le_bytes().to_vec(),
            });
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// A PSBT must have an unsigned transaction.
    MissingUnsignedTx,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            MissingUnsignedTx => write!(f, "serialized PSBT is missing unsigned tx "),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => Some(e),
            DeserPair(ref e) => Some(e),
            MissingUnsignedTx => None,
        }
    }
}

impl From<InsertPairError> for DecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Error consensus deserializing value.
    Consensus(encode::Error),
    /// Value was not the correct length (got, want).
    // TODO: Use struct instead of tuple.
    ValueWrongLength(usize, usize),
    /// PSBT_GLOBAL_VERSION: PSBT v0 expects the version to be 0.
    WrongVersion(u32),
    /// PSBT_GLOBAL_UNSIGNED_TX: Data is not consumed entirely.
    PartialDataConsumption,
    /// PSBT_GLOBAL_XPUB: Must contain 4 bytes for the xpub fingerprint.
    XpubInvalidFingerprint,
    /// PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints.
    XpubInvalidPath(usize),
    /// PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// PSBT_GLOBAL_XPUB: xpubs must be unique.
    DuplicateXpub(KeySource),
    /// PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key.
    InvalidProprietaryKey,
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
            Consensus(ref e) => write_err!(f, "error consensus deserializing type"; e),
            ValueWrongLength(got, want) =>
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want),
            WrongVersion(v) =>
                write!(f, "PSBT_GLOBAL_VERSION: PSBT v0 expects the version to be 0, found: {}", v),
            PartialDataConsumption => write!(f, "data not consumed entirely while deserializing"),
            XpubInvalidFingerprint =>
                write!(f, "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints"),
            XpubInvalidPath(len) => write!(
                f,
                "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints: {}",
                len
            ),
            Bip32(ref e) => write_err!(f, "PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type"; e),
            DuplicateXpub((fingerprint, ref derivation_path)) => write!(
                f,
                "PSBT_GLOBAL_XPUB: xpubs must be unique ({}, {})",
                fingerprint, derivation_path
            ),
            InvalidProprietaryKey => write!(f, "PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InsertPairError::*;

        match *self {
            Deser(ref e) => Some(e),
            Consensus(ref e) => Some(e),
            Bip32(ref e) => Some(e),
            DuplicateKey(_)
            | InvalidKeyDataEmpty(_)
            | InvalidKeyDataNotEmpty(_)
            | ValueWrongLength(..)
            | WrongVersion(_)
            | XpubInvalidFingerprint
            | XpubInvalidPath(_)
            | DuplicateXpub(_)
            | InvalidProprietaryKey
            | PartialDataConsumption => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

impl From<encode::Error> for InsertPairError {
    fn from(e: encode::Error) -> Self { Self::Consensus(e) }
}

impl From<bip32::Error> for InsertPairError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}
