// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Schnorr Bitcoin keys.
//!
//! This module provides Schnorr keys used in Bitcoin, reexporting Secp256k1
//! Schnorr key types.
//!

use core::fmt;

use bitcoin_internals::write_err;

pub use secp256k1::{self, constants, Secp256k1, KeyPair, XOnlyPublicKey, Verification};

use crate::prelude::*;

use crate::taproot::{TapBranchHash, TapTweakHash};
use crate::sighash::SchnorrSighashType;

/// Untweaked BIP-340 X-coord-only public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-340 X-coord-only public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Untweaked BIP-340 key pair
pub type UntweakedKeyPair = KeyPair;

/// Tweaked BIP-340 key pair
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedKeyPair(KeyPair);

/// A trait for tweaking BIP340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information
    type TweakedAux;
    /// Tweaked key type
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree merkle
    /// root. For the [`KeyPair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`]
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, secp256k1::Parity);
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> (TweakedPublicKey, secp256k1::Parity) {
        let tweak = TapTweakHash::from_key_and_tweak(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(secp, &tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(secp, &output_key, parity, tweak));
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}

impl TapTweak for UntweakedKeyPair {
    type TweakedAux = TweakedKeyPair;
    type TweakedKey = TweakedKeyPair;

    /// Tweaks private and public keys within an untweaked [`KeyPair`] with corresponding public key
    /// value and optional script tree merkle root.
    ///
    /// This is done by tweaking private key within the pair using the equation q = p + H(P|c), where
    ///  * q is the tweaked private key
    ///  * p is the internal private key
    ///  * H is the hash function
    ///  * c is the commitment data
    /// The public key is generated from a private key by multiplying with generator point, Q = qG.
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> TweakedKeyPair {
        let (pubkey, _parity) = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_tweak(pubkey, merkle_root).to_scalar();
        let tweaked = self.add_xonly_tweak(secp, &tweak).expect("Tap tweak failed");
        TweakedKeyPair(tweaked)
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeyPair {
        TweakedKeyPair(self)
    }
}

impl TweakedPublicKey {
    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn to_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] {
        self.0.serialize()
    }
}

impl TweakedKeyPair {
    /// Creates a new [`TweakedKeyPair`] from a [`KeyPair`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedKeyPair`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(pair: KeyPair) -> TweakedKeyPair {
        TweakedKeyPair(pair)
    }

    /// Returns the underlying key pair.
    #[inline]
    pub fn to_inner(self) -> KeyPair {
        self.0
    }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self {
        pair.0
    }
}

impl From<TweakedKeyPair> for KeyPair {
    #[inline]
    fn from(pair: TweakedKeyPair) -> Self {
        pair.0
    }
}

/// A BIP340-341 serialized schnorr signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: SchnorrSighashType,
}

impl Signature {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        match sl.len() {
            64 => {
                // default type
                let sig = secp256k1::schnorr::Signature::from_slice(sl)
                    .map_err(Error::Secp256k1)?;
                Ok(Signature { sig, hash_ty: SchnorrSighashType::Default })
            },
            65 => {
                let (hash_ty, sig) = sl.split_last().expect("Slice len checked == 65");
                let hash_ty = SchnorrSighashType::from_consensus_u8(*hash_ty)
                    .map_err(|_| Error::InvalidSighashType(*hash_ty))?;
                let sig = secp256k1::schnorr::Signature::from_slice(sig)
                    .map_err(Error::Secp256k1)?;
                Ok(Signature { sig, hash_ty })
            }
            len => {
                Err(Error::InvalidSignatureSize(len))
            }
        }
    }

    /// Serialize Signature
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if self.hash_ty == SchnorrSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }

}

/// A schnorr sig related error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid schnorr signature size
    InvalidSignatureSize(usize),
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidSighashType(hash_ty) =>
                write!(f, "Invalid signature hash type {}", hash_ty),
            Error::Secp256k1(ref e) =>
                write_err!(f, "Schnorr signature has correct len but is malformed"; e),
            Error::InvalidSignatureSize(sz) =>
                write!(f, "Invalid Schnorr signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Secp256k1(e) => Some(e),
            InvalidSighashType(_) | InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for Error {

    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}
