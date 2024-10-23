// SPDX-License-Identifier: CC0-1.0

//! A PSBT output.

use secp256k1::XOnlyPublicKey;

use super::{map, raw};
use crate::bip32::KeySource;
use crate::prelude::{BTreeMap, Vec};
use crate::script::ScriptBuf;
use crate::taproot::{TapLeafHash, TapTree};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    /// Creates an `Output` from a serializable [`Output`].
    ///
    /// [`Output`]: crate::psbt::map::Output
    pub fn from_serializable(output: map::Output) -> Self {
        Self {
            redeem_script: output.redeem_script,
            witness_script: output.witness_script,
            bip32_derivation: output.bip32_derivation,
            tap_internal_key: output.tap_internal_key,
            tap_tree: output.tap_tree,
            tap_key_origins: output.tap_key_origins,
            proprietary: output.proprietary,
            unknown: output.unknown,
        }
    }

    /// Converts this `Output` outto a serializable [`Output`].
    ///
    /// [`Output`]: crate::psbt::map::Output
    pub fn into_serializable(self) -> map::Output {
        map::Output {
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            tap_internal_key: self.tap_internal_key,
            tap_tree: self.tap_tree,
            tap_key_origins: self.tap_key_origins,
            proprietary: self.proprietary,
            unknown: self.unknown,
        }
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
