// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;
use core;
use core::convert::TryFrom;

use crate::io;

use crate::blockdata::script::Script;
use crate::consensus::encode;
use secp256k1::XOnlyPublicKey;
use crate::util::bip32::KeySource;
use secp256k1;
use crate::util::psbt::map::Map;
use crate::util::psbt::raw;
use crate::util::psbt::Error;

use crate::util::taproot::{ScriptLeaf, TapLeafHash};

use crate::util::taproot::{NodeInfo, TaprootBuilder};

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
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
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

/// Error happening when [`TapTree`] is constructed from a [`TaprootBuilder`]
/// having hidden branches or not being finalized.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum IncompleteTapTree {
    /// Indicates an attempt to construct a tap tree from a builder containing incomplete branches.
    NotFinalized(TaprootBuilder),
    /// Indicates an attempt to construct a tap tree from a builder containing hidden parts.
    HiddenParts(TaprootBuilder),
}

impl IncompleteTapTree {
    /// Converts error into the original incomplete [`TaprootBuilder`] instance.
    pub fn into_builder(self) -> TaprootBuilder {
        match self {
            IncompleteTapTree::NotFinalized(builder) |
            IncompleteTapTree::HiddenParts(builder) => builder
        }
    }
}

impl core::fmt::Display for IncompleteTapTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            IncompleteTapTree::NotFinalized(_) => "an attempt to construct a tap tree from a builder containing incomplete branches.",
            IncompleteTapTree::HiddenParts(_) => "an attempt to construct a tap tree from a builder containing hidden parts.",
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for IncompleteTapTree {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::IncompleteTapTree::*;

        match self {
            NotFinalized(_) | HiddenParts(_) => None,
        }
    }
}

/// Taproot Tree representing a finalized [`TaprootBuilder`] (a complete binary tree).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct TapTree(pub(crate) TaprootBuilder);

impl PartialEq for TapTree {
    fn eq(&self, other: &Self) -> bool {
        self.node_info().hash.eq(&other.node_info().hash)
    }
}

impl core::hash::Hash for TapTree {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.node_info().hash(state)
    }
}

impl Eq for TapTree {}

impl From<TapTree> for TaprootBuilder {
    #[inline]
    fn from(tree: TapTree) -> Self {
        tree.into_builder()
    }
}

impl TapTree {
    /// Gets the inner node info as the builder is finalized.
    pub fn node_info(&self) -> &NodeInfo {
        // The builder algorithm invariant guarantees that is_complete builder
        // have only 1 element in branch and that is not None.
        // We make sure that we only allow is_complete builders via the from_inner
        // constructor
        self.0.branch()[0].as_ref().expect("from_inner only parses is_complete builders")
    }

    /// Constructs [`TapTree`] from a [`TaprootBuilder`] if it is complete binary tree.
    ///
    /// # Returns
    /// A [`TapTree`] iff the `builder` is complete, otherwise return [`IncompleteTapTree`]
    /// error with the content of incomplete `builder` instance.
    #[deprecated(since = "0.29.0", note = "use try_from instead")]
    pub fn from_builder(builder: TaprootBuilder) -> Result<Self, IncompleteTapTree> {
        Self::try_from(builder)
    }


    /// Converts self into builder [`TaprootBuilder`]. The builder is guaranteed to be finalized.
    pub fn into_builder(self) -> TaprootBuilder {
        self.0
    }

    /// Constructs [`TaprootBuilder`] by internally cloning the `self`. The builder is guaranteed
    /// to be finalized.
    pub fn to_builder(&self) -> TaprootBuilder {
        self.0.clone()
    }

    /// Returns [`TapTreeIter<'_>`] iterator for a taproot script tree, operating in DFS order over
    /// tree [`ScriptLeaf`]s.
    pub fn script_leaves(&self) -> TapTreeIter {
        match (self.0.branch().len(), self.0.branch().last()) {
            (1, Some(Some(root))) => {
                TapTreeIter {
                    leaf_iter: root.leaves.iter()
                }
            }
            // This should be unreachable as we Taptree is already finalized
            _ => unreachable!("non-finalized tree builder inside TapTree"),
        }
    }
}

impl TryFrom<TaprootBuilder> for TapTree {
    type Error = IncompleteTapTree;

    /// Constructs [`TapTree`] from a [`TaprootBuilder`] if it is complete binary tree.
    ///
    /// # Returns
    /// A [`TapTree`] iff the `builder` is complete, otherwise return [`IncompleteTapTree`]
    /// error with the content of incomplete `builder` instance.
    fn try_from(builder: TaprootBuilder) -> Result<Self, Self::Error> {
        if !builder.is_finalizable() {
            Err(IncompleteTapTree::NotFinalized(builder))
        } else if builder.has_hidden_nodes() {
            Err(IncompleteTapTree::HiddenParts(builder))
        } else {
            Ok(TapTree(builder))
        }
    }
}

/// Iterator for a taproot script tree, operating in DFS order over leaf depth and
/// leaf script pairs.
pub struct TapTreeIter<'tree> {
    leaf_iter: core::slice::Iter<'tree, ScriptLeaf>,
}

impl<'tree> Iterator for TapTreeIter<'tree> {
    type Item = &'tree ScriptLeaf;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.leaf_iter.next()
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
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
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
}

impl_psbtmap_consensus_enc_dec_oding!(Output);
