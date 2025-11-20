// SPDX-License-Identifier: CC0-1.0

//! Cryptography support for the rust-bitcoin ecosystem.

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::convert::Infallible;
use core::fmt;

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

hashes::impl_hex_for_newtype!(TapLeafHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapLeafHash);

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

hashes::impl_hex_for_newtype!(TapTweakHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapTweakHash);

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> Self { Self::from_byte_array(leaf.to_byte_array()) }
}

/// The leaf version for tapleafs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafVersion {
    /// BIP-0342 tapscript.
    TapScript,

    /// Future leaf version.
    Future(FutureLeafVersion),
}

impl LeafVersion {
    /// Constructs a new [`LeafVersion`] from consensus byte representation.
    ///
    /// # Errors
    ///
    /// - If the last bit of the `version` is odd.
    /// - If the `version` is 0x50 ([`TAPROOT_ANNEX_PREFIX`]).
    pub fn from_consensus(version: u8) -> Result<Self, InvalidTaprootLeafVersionError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => Ok(Self::TapScript),
            TAPROOT_ANNEX_PREFIX => Err(InvalidTaprootLeafVersionError(TAPROOT_ANNEX_PREFIX)),
            future => FutureLeafVersion::from_consensus(future).map(LeafVersion::Future),
        }
    }

    /// Returns the consensus representation of this [`LeafVersion`].
    pub fn to_consensus(self) -> u8 {
        match self {
            Self::TapScript => TAPROOT_LEAF_TAPSCRIPT,
            Self::Future(version) => version.to_consensus(),
        }
    }
}

impl fmt::Display for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self, f.alternate()) {
            (Self::TapScript, true) => f.write_str("tapscript"),
            (Self::TapScript, false) => fmt::Display::fmt(&TAPROOT_LEAF_TAPSCRIPT, f),
            (Self::Future(version), true) => write!(f, "future_script_{:#02x}", version.0),
            (Self::Future(version), false) => fmt::Display::fmt(version, f),
        }
    }
}

impl fmt::LowerHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_consensus(), f)
    }
}
internals::impl_to_hex_from_lower_hex!(LeafVersion, |_| 2);

impl fmt::UpperHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.to_consensus(), f)
    }
}

/// Serializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
impl serde::Serialize for LeafVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.to_consensus())
    }
}

/// Deserializes [`LeafVersion`] as a `u8` using consensus encoding.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LeafVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct U8Visitor;
        impl serde::de::Visitor<'_> for U8Visitor {
            type Value = LeafVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid consensus-encoded Taproot leaf version")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = u8::try_from(value).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Unsigned(value),
                        &"consensus-encoded leaf version as u8",
                    )
                })?;
                LeafVersion::from_consensus(value).map_err(|_| {
                    E::invalid_value(
                        ::serde::de::Unexpected::Unsigned(value as u64),
                        &"consensus-encoded leaf version as u8",
                    )
                })
            }
        }

        deserializer.deserialize_u8(U8Visitor)
    }
}

/// Inner type representing future (non-tapscript) leaf versions. See [`LeafVersion::Future`].
///
/// NB: NO PUBLIC CONSTRUCTOR!
/// The only way to construct this is by converting `u8` to [`LeafVersion`] and then extracting it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FutureLeafVersion(u8);

impl FutureLeafVersion {
    pub(self) fn from_consensus(version: u8) -> Result<Self, InvalidTaprootLeafVersionError> {
        match version {
            TAPROOT_LEAF_TAPSCRIPT => unreachable!(
                "FutureLeafVersion::from_consensus should never be called for 0xC0 value"
            ),
            TAPROOT_ANNEX_PREFIX => Err(InvalidTaprootLeafVersionError(TAPROOT_ANNEX_PREFIX)),
            odd if odd & 0xFE != odd => Err(InvalidTaprootLeafVersionError(odd)),
            even => Ok(Self(even)),
        }
    }

    /// Returns the consensus representation of this [`FutureLeafVersion`].
    #[inline]
    pub fn to_consensus(self) -> u8 { self.0 }
}

impl fmt::Display for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}
internals::impl_to_hex_from_lower_hex!(FutureLeafVersion, |_| 2);

impl fmt::UpperHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

/// The last bit of tapleaf version must be zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTaprootLeafVersionError(u8);

impl InvalidTaprootLeafVersionError {
    /// Accessor for the invalid leaf version.
    pub fn invalid_leaf_version(&self) -> u8 { self.0 }
}

impl From<Infallible> for InvalidTaprootLeafVersionError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for InvalidTaprootLeafVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "leaf version({}) must have the least significant bit 0", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidTaprootLeafVersionError {}
