// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot.
//!
//! This module provides support for Taproot tagged hashes.

use hashes::{hash_newtype, sha256t, sha256t_tag};

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_tag! {
    #[derive(Debug)]
    pub struct TapLeafTag = hash_str("TapLeaf");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapLeaf\".
    ///
    /// This is used for computing tapscript script spend hash.
    pub struct TapLeafHash(sha256t::Hash<TapLeafTag>);
}

hashes::impl_hex_for_newtype!(TapLeafHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapLeafHash);

sha256t_tag! {
    #[derive(Debug)]
    pub struct TapBranchTag = hash_str("TapBranch");
}

hash_newtype! {
    /// Tagged hash used in Taproot trees.
    ///
    /// See BIP-340 for tagging rules.
    pub struct TapNodeHash(sha256t::Hash<TapBranchTag>);
}

hashes::impl_hex_for_newtype!(TapNodeHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapNodeHash);

sha256t_tag! {
    #[derive(Debug)]
    pub struct TapTweakTag = hash_str("TapTweak");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapTweak\".
    ///
    /// This hash type is used while computing the tweaked public key.
    pub struct TapTweakHash(sha256t::Hash<TapTweakTag>);
}

hashes::impl_hex_for_newtype!(TapTweakHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapTweakHash);

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> TapNodeHash { TapNodeHash::from_byte_array(leaf.to_byte_array()) }
}
