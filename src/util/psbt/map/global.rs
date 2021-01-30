// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use prelude::*;

use io::{self, Cursor, Read};
use core::cmp;

use blockdata::transaction::Transaction;
use consensus::{encode, Encodable, Decodable};
use consensus::encode::MAX_VEC_SIZE;
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt;
use util::psbt::Error;
use util::endian::u32_to_array_le;
use util::bip32::{ExtendedPubKey, KeySource, Fingerprint, DerivationPath, ChildNumber};

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

/// A key-value map for global data.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Global {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be
    /// empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Global {
    /// Create a Global from an unsigned transaction, error if not unsigned
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, psbt::Error> {
        for txin in &tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(Global {
            unsigned_tx: tx,
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        })
    }
}

impl Map for Global {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_GLOBAL_UNSIGNED_TX => return Err(Error::DuplicateKey(raw_key).into()),
            PSBT_GLOBAL_PROPRIETARY => match self.proprietary.entry(raw::ProprietaryKey::from_key(raw_key.clone())?) {
                btree_map::Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            }
        }

        Ok(())
    }

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

    // Keep in mind that according to BIP 174 this function must be commutative, i.e.
    // A.merge(B) == B.merge(A)
    fn merge(&mut self, other: Self) -> Result<(), psbt::Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(psbt::Error::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                },
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if derivation1 == derivation2 && fingerprint1 == fingerprint2
                    {
                        continue
                    }
                    else if
                        derivation1.len() < derivation2.len() &&
                        derivation1[..] == derivation2[derivation2.len() - derivation1.len()..]
                    {
                        continue
                    }
                    else if derivation2[..] == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue
                    }
                    return Err(psbt::Error::MergeInconsistentKeySources(xpub));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl_psbtmap_consensus_encoding!(Global);

impl Decodable for Global {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let mut d = d.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::consensus_decode(&mut d) {
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
                        PSBT_GLOBAL_PROPRIETARY => match proprietary.entry(raw::ProprietaryKey::from_key(pair.key.clone())?) {
                            btree_map::Entry::Vacant(empty_key) => {empty_key.insert(pair.value);},
                            btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(pair.key).into()),
                        }
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {empty_key.insert(pair.value);},
                            btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
                        }
                    }
                }
                Err(::consensus::encode::Error::Psbt(::util::psbt::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        if let Some(tx) = tx {
            let mut rv: Global = Global::from_unsigned_tx(tx)?;
            rv.version = version.unwrap_or(0);
            rv.xpub = xpub_map;
            rv.unknown = unknowns;
            rv.proprietary = proprietary;
            Ok(rv)
        } else {
            Err(Error::MustHaveUnsignedTx.into())
        }
    }
}
