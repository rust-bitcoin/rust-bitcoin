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

use io;

use blockdata::script::Script;
use consensus::encode;
use secp256k1::XOnlyPublicKey;
use util::bip32::KeySource;
use secp256k1;
use util::psbt;
use util::psbt::map::Map;
use util::psbt::raw;
use util::psbt::Error;

use util::taproot::TapLeafHash;

use util::taproot::{NodeInfo, TaprootBuilder};

/// Type: Redeem Script PSBT_OUT_REDEEM_SCRIPT = 0x00
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness Script PSBT_OUT_WITNESS_SCRIPT = 0x01
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
#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

/// Taproot Tree representing a finalized [`TaprootBuilder`] (a complete binary tree).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TapTree(pub(crate) TaprootBuilder);

impl PartialEq for TapTree {
    fn eq(&self, other: &Self) -> bool {
        self.node_info().hash.eq(&other.node_info().hash)
    }
}

impl Eq for TapTree {}

impl TapTree {
    /// Gets the inner node info as the builder is finalized.
    fn node_info(&self) -> &NodeInfo {
        // The builder algorithm invariant guarantees that is_complete builder
        // have only 1 element in branch and that is not None.
        // We make sure that we only allow is_complete builders via the from_inner
        // constructor
        self.0.branch()[0].as_ref().expect("from_inner only parses is_complete builders")
    }

    /// Converts a [`TaprootBuilder`] into a tree if it is complete binary tree.
    ///
    /// # Return
    /// A `TapTree` iff the `inner` builder is complete, otherwise return the inner as `Err`.
    pub fn from_inner(inner: TaprootBuilder) -> Result<Self, TaprootBuilder> {
        if inner.is_complete() {
            Ok(TapTree(inner))
        } else {
            Err(inner)
        }
    }

    /// Converts self into builder [`TaprootBuilder`]. The builder is guaranteed to be finalized.
    pub fn into_inner(self) -> TaprootBuilder {
        self.0
    }
}

impl Output {
    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    },
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
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
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            }
        }

        Ok(())
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error> {
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

        Ok(rv)
    }

    fn merge(&mut self, other: Self) -> Result<(), psbt::Error> {
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        self.tap_key_origins.extend(other.tap_key_origins);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(tap_internal_key, self, other);
        merge!(tap_tree, self, other);

        Ok(())
    }
}

impl_psbtmap_consensus_enc_dec_oding!(Output);
