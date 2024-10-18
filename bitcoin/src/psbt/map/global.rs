// SPDX-License-Identifier: CC0-1.0

use internals::ToU64 as _;
use io::BufRead;

use crate::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use crate::consensus::encode::MAX_VEC_SIZE;
use crate::consensus::{self, encode};
use crate::locktime::absolute;
use crate::prelude::{btree_map, BTreeMap, Vec};
use crate::psbt::map::Map;
use crate::psbt::{raw, Error, Psbt};
use crate::transaction::{self, Transaction};

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u64 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u64 = 0x01;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u64 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u64 = 0xFC;

impl Map for Psbt {
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

impl Psbt {
    pub(crate) fn decode_global<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut r = r.take(MAX_VEC_SIZE.to_u64());
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSBT_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key_data.is_empty() {
                                // there can only be one unsigned transaction
                                if tx.is_none() {
                                    let vlen: usize = pair.value.len();

                                    // Manually deserialized to ensure 0-input
                                    // txs without witnesses are deserialized
                                    // properly.
                                    let buf = &pair.value[..];
                                    let mut start = 0;

                                    let (version, size) =
                                        consensus::deserialize_partial::<transaction::Version>(
                                            &buf[start..],
                                        )?;
                                    start += size;

                                    let (input, size) =
                                        consensus::deserialize_partial::<Vec<transaction::TxIn>>(
                                            &buf[start..],
                                        )?;
                                    start += size;

                                    let (output, size) =
                                        consensus::deserialize_partial::<Vec<transaction::TxOut>>(
                                            &buf[start..],
                                        )?;
                                    start += size;

                                    let (lock_time, size) =
                                        consensus::deserialize_partial::<absolute::LockTime>(
                                            &buf[start..],
                                        )?;
                                    start += size;

                                    tx = Some(Transaction { version, input, output, lock_time });

                                    if start != vlen {
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
                            if !pair.key.key_data.is_empty() {
                                let xpub = Xpub::decode(&pair.key.key_data)
                                    .map_err(|_| Error::XPubKey(
                                        "can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(Error::XPubKey(
                                        "incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let buf = &pair.value[..];
                                let mut start = 0;
                                let (fingerprint, size) =
                                    consensus::deserialize_partial::<[u8; 4]>(&buf[start..])
                                        .map_err(|_| {
                                            Error::XPubKey("can't read global xpub fingerprint")
                                        })?;
                                debug_assert_eq!(size, 4);
                                start += size;

                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok((index, size)) =
                                    consensus::deserialize_partial::<u32>(&buf[start..])
                                {
                                    path.push(ChildNumber::from(index));
                                    start += size;
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(fingerprint), derivation))
                                    .is_some()
                                {
                                    return Err(Error::XPubKey("repeated global xpub key"));
                                }
                            } else {
                                return Err(Error::XPubKey(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSBT_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key_data.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    if vlen != 4 {
                                        return Err(Error::Version(
                                            "invalid global version value length (must be 4 bytes)",
                                        ));
                                    }
                                    version = Some(consensus::deserialize::<u32>(&pair.value)?);
                                    // We only understand version 0 PSBTs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0.
                                    if version != Some(0) {
                                        return Err(Error::Version(
                                            "PSBT versions greater than 0 are not supported",
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

        if let Some(tx) = tx {
            Ok(Psbt {
                unsigned_tx: tx,
                version: version.unwrap_or(0),
                xpub: xpub_map,
                proprietary,
                unknown: unknowns,
                inputs: vec![],
                outputs: vec![],
            })
        } else {
            Err(Error::MustHaveUnsignedTx)
        }
    }
}
