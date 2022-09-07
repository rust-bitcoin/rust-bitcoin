// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use crate::prelude::*;

use crate::io::{self, Cursor, Read};

use crate::blockdata::transaction::Transaction;
use crate::consensus::{encode, Encodable, Decodable};
use crate::consensus::encode::MAX_VEC_SIZE;
use crate::util::psbt::map::Map;
use crate::util::psbt::{raw, PartiallySignedTransaction};
use crate::util::psbt::Error;
use crate::util::endian::u32_to_array_le;
use crate::util::bip32::{ExtendedPubKey, Fingerprint, DerivationPath, ChildNumber};

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

impl Map for PartiallySignedTransaction {
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSBT_GLOBAL_UNSIGNED_TX,
                key: vec![],
            },
            value: {
                // Manually serialized to ensure 0-input txs are serialized
                // without witnesses.
                let mut ret = Vec::new();
                self.unsigned_tx.version.consensus_encode(&mut ret)?;
                self.unsigned_tx.input.consensus_encode(&mut ret)?;
                self.unsigned_tx.output.consensus_encode(&mut ret)?;
                self.unsigned_tx.lock_time.consensus_encode(&mut ret)?;
                ret
            },
        });

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSBT_GLOBAL_XPUB,
                    key: xpub.encode().to_vec(),
                },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32_to_array_le((*n).into())));
                    ret
                }
            });
        }

        // Serializing version only for non-default value; otherwise test vectors fail
        if self.version > 0 {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSBT_GLOBAL_VERSION,
                    key: vec![],
                },
                value: u32_to_array_le(self.version).to_vec()
            });
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair {
                key: key.to_key(),
                value: value.clone(),
            });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair {
                key: key.clone(),
                value: value.clone(),
            });
        }

        Ok(rv)
    }
}

impl PartiallySignedTransaction {
    pub(crate) fn consensus_decode_global<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::consensus_decode(&mut r) {
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
                                        return Err(encode::Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into())
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into())
                            }
                        }
                        PSBT_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = ExtendedPubKey::decode(&pair.key.key)
                                    .map_err(|_| encode::Error::ParseFailed(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(encode::Error::ParseFailed("Incorrect length of global xpub derivation data"))
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map.insert(xpub, (Fingerprint::from(&fingerprint[..]), derivation)).is_some() {
                                    return Err(encode::Error::ParseFailed("Repeated global xpub key"))
                                }
                            } else {
                                return Err(encode::Error::ParseFailed("Xpub global key must contain serialized Xpub data"))
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
                                        return Err(encode::Error::ParseFailed("Wrong global version value length (must be 4 bytes)"))
                                    }
                                    version = Some(Decodable::consensus_decode(&mut decoder)?);
                                    // We only understand version 0 PSBTs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0.
                                    if version != Some(0) {
                                        return Err(encode::Error::ParseFailed("PSBT versions greater than 0 are not supported"))
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into())
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into())
                            }
                        }
                        PSBT_GLOBAL_PROPRIETARY => match proprietary.entry(raw::ProprietaryKey::try_from(pair.key.clone())?) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            },
                            btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(pair.key).into()),
                        }
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            },
                            btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
                        }
                    }
                }
                Err(crate::consensus::encode::Error::Psbt(crate::util::psbt::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        if let Some(tx) = tx {
            Ok(PartiallySignedTransaction {
                unsigned_tx: tx,
                version: version.unwrap_or(0),
                xpub: xpub_map,
                proprietary,
                unknown: unknowns,
                inputs: vec![],
                outputs: vec![]
            })
        } else {
            Err(Error::MustHaveUnsignedTx.into())
        }
    }
}
