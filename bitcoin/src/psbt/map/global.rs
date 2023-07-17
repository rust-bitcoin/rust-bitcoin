// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use crate::absolute::LockTime;
use crate::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::MAX_VEC_SIZE;
use crate::consensus::{encode, Decodable};
use crate::io::{self, Cursor, Read};
use crate::prelude::*;
use crate::psbt::map::Map;
use crate::psbt::{raw, Error, Input, Output, Psbt, PsbtInner, TxModifiable, Version};
use crate::VarInt;

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Global Transaction Version PSBT_GLOBAL_TX_VERSION = 0x02
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
/// Type: Fallback Locktime PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// Type: Input Count PSBT_GLOBAL_INPUT_COUNT = 0x04
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// Type: Output Count PSBT_GLOBAL_OUTPUT_COUNT = 0x05
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// Type: Transaction Modification flags PSBT_GLOBAL_TX_MODIFIABLE = 0x06
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

impl Map for Psbt {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();
        let inner = &self.inner;

        if inner.version == Version::PsbtV0 {
            let unsigned_tx = inner.unsigned_tx.as_ref().unwrap();
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_UNSIGNED_TX, key: vec![] },
                value: {
                    // Manually serialized to ensure 0-input txs are serialized
                    // without witnesses.
                    let mut ret = Vec::new();
                    ret.extend(encode::serialize(&unsigned_tx.version));
                    ret.extend(encode::serialize(&unsigned_tx.input));
                    ret.extend(encode::serialize(&unsigned_tx.output));
                    ret.extend(encode::serialize(&unsigned_tx.lock_time));
                    ret
                },
            });
        }

        for (xpub, (fingerprint, derivation)) in &inner.xpub {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }

        // Serializing version only for non-default value; otherwise test vectors fail
        if inner.version > Version::PsbtV0 {
            // BIP 370 introduced breaking changes to the existing PsbtV0 standard (BIP 174).
            // It is assumed here that the next versions contain the following new fields.
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_TX_VERSION, key: vec![] },
                value: inner.tx_version.unwrap().to_le_bytes().to_vec(),
            });

            // Optional in PsbtV2
            if let Some(fallback_locktime) = inner.fallback_locktime.as_ref() {
                rv.push(raw::Pair {
                    key: raw::Key { type_value: PSBT_GLOBAL_FALLBACK_LOCKTIME, key: vec![] },
                    value: fallback_locktime.to_consensus_u32().to_be_bytes().to_vec(),
                });
            }

            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_INPUT_COUNT, key: vec![] },
                value: encode::serialize(&VarInt(inner.inputs.len() as u64)),
            });

            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_OUTPUT_COUNT, key: vec![] },
                value: encode::serialize(&VarInt(inner.outputs.len() as u64)),
            });

            // Optional in PsbtV2
            if let Some(tx_modifiable) = inner.tx_modifiable.as_ref() {
                rv.push(raw::Pair {
                    key: raw::Key { type_value: PSBT_GLOBAL_TX_MODIFIABLE, key: vec![] },
                    value: vec![tx_modifiable.to_raw()],
                });
            }

            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key: vec![] },
                value: inner.version.to_raw().to_le_bytes().to_vec(),
            });
        }

        for (key, value) in inner.proprietary.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in inner.unknown.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

impl Psbt {
    pub(crate) fn decode_global<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut tx_version: Option<i32> = None;
        let mut fallback_locktime: Option<LockTime> = None;
        let mut input_count: Option<VarInt> = None;
        let mut output_count: Option<VarInt> = None;
        let mut tx_modifiable: Option<TxModifiable> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSBT_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
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

                                    if decoder.position() != vlen as u64 {
                                        return Err(Error::PartialDataConsumption);
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = Xpub::decode(&pair.key.key)
                                    .map_err(|_| Error::XPubKey(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(Error::XPubKey(
                                        "Incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..]).map_err(|_| {
                                    Error::XPubKey("Can't read global xpub fingerprint")
                                })?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(fingerprint), derivation))
                                    .is_some()
                                {
                                    return Err(Error::XPubKey("Repeated global xpub key"));
                                }
                            } else {
                                return Err(Error::XPubKey(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSBT_GLOBAL_TX_VERSION => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one tx_version
                                if tx_version.is_none() {
                                    let mut decoder = Cursor::new(pair.value);
                                    tx_version = Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_FALLBACK_LOCKTIME => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one fallback locktime
                                if fallback_locktime.is_none() {
                                    let mut decoder = Cursor::new(pair.value);
                                    fallback_locktime =
                                        Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_INPUT_COUNT => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one input count
                                if input_count.is_none() {
                                    let mut decoder = Cursor::new(pair.value);
                                    input_count = Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_OUTPUT_COUNT => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one output count
                                if output_count.is_none() {
                                    let mut decoder = Cursor::new(pair.value);
                                    output_count = Some(Decodable::consensus_decode(&mut decoder)?);
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_TX_MODIFIABLE => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one transaction modifiable flag
                                if tx_modifiable.is_none() {
                                    let mut decoder = Cursor::new(pair.value);
                                    let flags: u8 = Decodable::consensus_decode(&mut decoder)?;
                                    match TxModifiable::from_raw(flags) {
                                        Ok(modifiable) => {
                                            tx_modifiable = Some(modifiable);
                                        }
                                        Err(err) => {
                                            return Err(err);
                                        }
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(Error::Version(
                                            "invalid global version value length (must be 4 bytes)",
                                        ));
                                    }
                                    version = Some(Decodable::consensus_decode(&mut decoder)?);
                                    // We only understand version 0 and 2 PSBTs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0 and 2.
                                    if version != Some(0) && version != Some(2) {
                                        return Err(Error::Version(
                                            "PSBT versions other than 0 and 2 are not supported",
                                        ));
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_PROPRIETARY => match proprietary
                            .entry(raw::ProprietaryKey::try_from(pair.key.clone())?)
                        {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(Error::DuplicateKey(pair.key)),
                        },
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(k) =>
                                return Err(Error::DuplicateKey(k.key().clone())),
                        },
                    }
                }
                Err(crate::psbt::Error::NoMorePairs) => break,
                Err(e) => return Err(e),
            }
        }

        let inputs: Vec<Input>;
        let outputs: Vec<Output>;
        let version = match version {
            Some(v) => Version::from_raw(v).map_err(Error::from)?,
            None => Version::PsbtV0,
        };

        // According to BIP-370, PSBT_GLOBAL_INPUT_COUNT and PSBT_GLOBAL_OUTPUT_COUNT
        // are required in PsbtV2
        if version != Version::PsbtV0 {
            match (input_count, output_count) {
                (Some(input_count), Some(output_count)) => {
                    inputs = Vec::with_capacity(input_count.0 as usize);
                    outputs = Vec::with_capacity(output_count.0 as usize);
                }
                _ => return Err(Error::InvalidInputOutputCounts),
            }
        } else {
            // A PsbtV0 can not contain input and output counts
            if input_count.is_some() || output_count.is_some() {
                return Err(Error::InvalidInputOutputCounts);
            }
            inputs = vec![];
            outputs = vec![];
        }

        let psbt_inner = PsbtInner {
            unsigned_tx: tx,
            version,
            xpub: xpub_map,
            proprietary,
            unknown: unknowns,
            inputs,
            outputs,
            tx_modifiable,
            tx_version,
            fallback_locktime,
        };

        Psbt::new(psbt_inner)
    }
}
