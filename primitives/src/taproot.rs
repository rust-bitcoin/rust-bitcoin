// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot.
//!
//! This module provides support for Taproot tagged hashes.

use hashes::{hash_newtype, sha256t, sha256t_tag};

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_tag! {
    pub struct TapLeafTag = hash_str("TapLeaf");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapLeaf\".
    ///
    /// This is used for computing tapscript script spend hash.
    pub struct TapLeafHash(sha256t::Hash<TapLeafTag>);
}

sha256t_tag! {
    pub struct TapBranchTag = hash_str("TapBranch");
}

hash_newtype! {
    /// Tagged hash used in Taproot trees.
    ///
    /// See BIP-340 for tagging rules.
    pub struct TapNodeHash(sha256t::Hash<TapBranchTag>);
}

sha256t_tag! {
    pub struct TapTweakTag = hash_str("TapTweak");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapTweak\".
    ///
    /// This hash type is used while computing the tweaked public key.
    pub struct TapTweakHash(sha256t::Hash<TapTweakTag>);
}

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> TapNodeHash { TapNodeHash::from_byte_array(leaf.to_byte_array()) }
}
