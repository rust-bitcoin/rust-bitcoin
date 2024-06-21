// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides pubkey hashes used in Bitcoin.

use hashes::hash160;

use crate::internal_macros;

hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}
internal_macros::impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

#[cfg(feature = "rand-std")]
pub use secp256k1::rand;

#[cfg(feature = "base58")]
pub use crate::crypto::key::FromWifError;
/// Re-export keys and sighash.
// This is done like this because we only want a single top level `key` module.
#[cfg(feature = "crypto")]
pub use crate::crypto::key::{
    CompressedPublicKey, FromSliceError, InvalidAddressVersionError,
    InvalidBase58PayloadLengthError, Keypair, ParseCompressedPublicKeyError, ParsePublicKeyError,
    PrivateKey, PublicKey, SortKey, TapTweak, TweakedKeypair, TweakedPublicKey,
    UncompressedPublicKeyError, UntweakedKeypair, UntweakedPublicKey, XOnlyPublicKey,
};
