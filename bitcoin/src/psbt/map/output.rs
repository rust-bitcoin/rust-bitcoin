// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;
use core;
use core::convert::TryFrom;

use crate::blockdata::script::ScriptBuf;
use secp256k1::XOnlyPublicKey;
use crate::bip32::KeySource;
use secp256k1;
use crate::psbt::map::Map;
use crate::psbt::raw;
use crate::psbt::Error;

use crate::taproot::{TapTree, TapLeafHash};

/// Type: Redeem ScriptBuf PSBT_OUT_REDEEM_SCRIPT = 0x00
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness ScriptBuf PSBT_OUT_WITNESS_SCRIPT = 0x01
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSBT_OUT_BIP32_DERIVATION = 0x02
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
/// Type: Taproot Internal Key PSBT_OUT_TAP_INTERNAL_KEY = 0x05
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
/// Type: Taproot Tree PSBT_OUT_TAP_TREE = 0x06
const PSBT_OUT_TAP_TREE: u8 = 0x06;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this output.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    },
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: XOnlyPublicKey>
                }
            }
            PSBT_OUT_TAP_TREE => {
                impl_psbt_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone())),
            }
        }

        Ok(())
    }

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        self.tap_key_origins.extend(other.tap_key_origins);

        combine!(redeem_script, self, other);
        combine!(witness_script, self, other);
        combine!(tap_internal_key, self, other);
        combine!(tap_tree, self, other);
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_OUT_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
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

        rv
    }
}

impl_psbtmap_ser_de_serialize!(Output);
