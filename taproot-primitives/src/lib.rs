// SPDX-License-Identifier: CC0-1.0

//! Taproot stuff destined for bitcoin-primitives.

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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;

pub extern crate hashes;
pub extern crate secp256k1;

#[cfg(feature = "serde")]
pub extern crate serde;

#[rustfmt::skip] // Keep pub re-exports separate
#[doc(no_inline)]
pub use self::error::InvalidTaprootLeafVersionError;

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use crypto::key::{
    TweakedKeypair, TweakedPublicKey, UntweakedKeypair, UntweakedPublicKey, XOnlyPublicKey,
};
use hashes::{hash_newtype, sha256t, sha256t_tag, HashEngine as _};
use secp256k1::Scalar;

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
#[cfg(feature = "hex")]
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

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TapNodeHash);
#[cfg(feature = "serde")]
#[cfg(feature = "hex")]
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
#[cfg(feature = "hex")]
hashes::impl_serde_for_newtype!(TapTweakHash);

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> Self { Self::from_byte_array(leaf.to_byte_array()) }
}

impl TapTweakHash {
    /// Converts a `TapTweakHash` into a `Scalar` ready for use with key tweaking API.
    #[allow(clippy::missing_panics_doc)]
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }

    /// Constructs a new BIP-0341 [`TapTweakHash`] from key and Merkle root. Produces `H_taptweak(P||R)` where
    /// `P` is the internal key and `R` is the Merkle root.
    pub fn from_key_and_merkle_root<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let mut eng = sha256t::Hash::<TapTweakTag>::engine();
        // always hash the key
        eng.input(&internal_key.serialize().0);
        if let Some(h) = merkle_root {
            eng.input(h.as_ref());
        } else {
            // nothing to hash
        }
        let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
        Self::from_byte_array(inner.to_byte_array())
    }
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
            (Self::Future(version), true) => write!(f, "future_script_{:#04x}", version.0),
            (Self::Future(version), false) => fmt::Display::fmt(version, f),
        }
    }
}

impl fmt::LowerHex for LeafVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_consensus(), f)
    }
}
#[cfg(feature = "alloc")]
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
                        ::serde::de::Unexpected::Unsigned(u64::from(value)),
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
    #[track_caller]
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
#[cfg(feature = "alloc")]
internals::impl_to_hex_from_lower_hex!(FutureLeafVersion, |_| 2);

impl fmt::UpperHex for FutureLeafVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

/// A trait for tweaking BIP-0340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information.
    type TweakedAux;
    /// Tweaked key type.
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree Merkle
    /// root. For the [`Keypair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key, with the required parity.
    ///
    /// [`Keypair`]: crypto::Keypair
    fn tap_tweak(&self, merkle_root: Option<TapNodeHash>) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`].
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = TweakedPublicKey;
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// Merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    ///
    /// The tweaked key and its parity.
    fn tap_tweak(&self, merkle_root: Option<TapNodeHash>) -> TweakedPublicKey {
        let tweak = TapTweakHash::from_key_and_merkle_root(*self, merkle_root).to_scalar();
        let output_key = self.add_tweak(&tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(&output_key, tweak));
        TweakedPublicKey::dangerous_assume_tweaked(output_key)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey::dangerous_assume_tweaked(self)
    }
}

impl TapTweak for UntweakedKeypair {
    type TweakedAux = TweakedKeypair;
    type TweakedKey = TweakedKeypair;

    /// Applies a Taproot tweak to both keys within the keypair.
    ///
    /// If `merkle_root` is provided, produces a Taproot key that can be spent by any
    /// of the script paths committed to by the root. If it is not provided, produces
    /// a Taproot key which can [provably only be spent via
    /// keyspend](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-23).
    ///
    /// # Returns
    ///
    /// The tweaked keypair.
    fn tap_tweak(&self, merkle_root: Option<TapNodeHash>) -> TweakedKeypair {
        let pubkey = XOnlyPublicKey::from_keypair(self);
        let tweak = TapTweakHash::from_key_and_merkle_root(pubkey, merkle_root).to_scalar();
        let tweaked = self.as_inner().add_xonly_tweak(&tweak).expect("Tap tweak failed");
        TweakedKeypair::dangerous_assume_tweaked(Self::from(tweaked))
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeypair {
        TweakedKeypair::dangerous_assume_tweaked(self)
    }
}

/// Error types for taproot primitives
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    /// The last bit of tapleaf version must be zero.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InvalidTaprootLeafVersionError(pub(super) u8);

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
    impl std::error::Error for InvalidTaprootLeafVersionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self(_) = self;
            None
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TapLeafHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TapNodeHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FutureLeafVersion {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u8::arbitrary(u)? {
            TAPROOT_LEAF_TAPSCRIPT => Err(arbitrary::Error::IncorrectFormat),
            version => Self::from_consensus(version).map_err(|_| arbitrary::Error::IncorrectFormat),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for LeafVersion {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match bool::arbitrary(u)? {
            true => Ok(Self::TapScript),
            false => Ok(Self::Future(u.arbitrary()?)),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod test {
    use super::*;

    #[test]
    fn leaf_version_future_fmt() {
        let v = LeafVersion::Future(FutureLeafVersion(1));
        assert_eq!(alloc::format!("{:#}", v), "future_script_0x01");
    }
}
