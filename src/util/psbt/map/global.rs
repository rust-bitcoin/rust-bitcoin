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

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Cursor, Read};

use blockdata::transaction::Transaction;
use consensus::{encode, Encodable, Decodable};
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt;
use util::psbt::Error;
use util::bip32::{ExtendedPubKey, KeySource, Fingerprint, DerivationPath, ChildNumber};

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;

/// A key-value map for global data.
#[derive(Clone, Debug, PartialEq)]
pub struct Global {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be
    /// empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,
    /// Unknown global key-value pairs.
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}
serde_struct_impl!(Global, unsigned_tx, version, xpub, unknown);

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
            _ => match self.unknown.entry(raw_key) {
                Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            }
        }

        Ok(())
    }

    fn get_pairs(&self) -> Result<Vec<raw::Pair>, encode::Error> {
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

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair {
                key: key.clone(),
                value: value.clone(),
            });
        }

        Ok(rv)
    }

    fn merge(&mut self, other: Self) -> Result<(), psbt::Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(psbt::Error::UnexpectedUnsignedTx {
                expected: self.unsigned_tx.clone(),
                actual: other.unsigned_tx,
            });
        }

        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl_psbtmap_consensus_encoding!(Global);

impl Decodable for Global {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {

        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> = Default::default();

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
                        // Global Xpub
                        0x01 => {
                            if !pair.key.key.is_empty() {
                                let xpub = ExtendedPubKey::decode(&pair.key.key)
                                    .map_err(|_| {
                                        encode::Error::ParseFailed("Can't deserialize ExtendedPublicKey from global XPUB key data")
                                    })?;

                                if pair.value.len() % 4 != 0 {
                                    return Err(encode::Error::ParseFailed("Incorrect length of global xpub list"))
                                }

                                let keys_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(keys_count);
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
                        // Version
                        0xFB => {
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
                        _ => match unknowns.entry(pair.key) {
                            Entry::Vacant(empty_key) => {empty_key.insert(pair.value);},
                            Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
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
            Ok(rv)
        } else {
            Err(Error::MustHaveUnsignedTx.into())
        }
    }
}
