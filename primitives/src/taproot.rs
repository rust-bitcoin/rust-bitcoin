// SPDX-License-Identifier: CC0-1.0

//! Taproot primitive types.

use hashes::{hash_newtype, sha256t, sha256t_tag};

/// Maximum depth of a Taproot tree script spend path.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L229
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Size of a Taproot control node.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L228
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Tapleaf mask for getting the leaf version from first byte of control block.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L225
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Tapscript leaf version.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L226
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Taproot annex prefix.
pub const TAPROOT_ANNEX_PREFIX: u8 = 0x50;
/// Tapscript control base size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L227
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Tapscript control max size.
// https://github.com/bitcoin/bitcoin/blob/e826b22da252e0599c61d21c98ff89f366b3120f/src/script/interpreter.h#L230
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

// Taproot test vectors from BIP-0341 state the hashes without any reversing
sha256t_tag! {
    pub struct TapLeafTag = hash_str("TapLeaf");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapLeaf\".
    ///
    /// This is used for computing tapscript script spend hash.
    pub struct TapLeafHash(sha256t::Hash<TapLeafTag>);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TapLeafHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapLeafHash);
hashes::impl_encodable!(TapLeafHash, 32); // FIXME: Get length from inner hash.

sha256t_tag! {
    pub struct TapBranchTag = hash_str("TapBranch");
}

hash_newtype! {
    /// Tagged hash used in Taproot trees.
    ///
    /// See BIP-0340 for tagging rules.
    #[repr(transparent)]
    pub struct TapNodeHash(sha256t::Hash<TapBranchTag>);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TapNodeHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapNodeHash);

sha256t_tag! {
    pub struct TapTweakTag = hash_str("TapTweak");
}

hash_newtype! {
    /// Taproot-tagged hash with tag \"TapTweak\".
    ///
    /// This hash type is used while computing the tweaked public key.
    pub struct TapTweakHash(sha256t::Hash<TapTweakTag>);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TapTweakHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapTweakHash);

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> TapNodeHash { TapNodeHash::from_byte_array(leaf.to_byte_array()) }
}
