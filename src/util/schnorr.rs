// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Schnorr Bitcoin keys.
//!
//! This module provides Schnorr keys used in Bitcoin, reexporting Secp256k1
//! Schnorr key types.
//!

use core::{fmt, str};
use prelude::*;

pub use secp256k1::{XOnlyPublicKey, KeyPair};
use secp256k1::{self, Secp256k1, Verification, constants};
use hashes::Hash;
use util::taproot::{TapBranchHash, TapTweakHash};
use SchnorrSigHashType;

/// Untweaked Schnorr public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked Schnorr public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl str::FromStr for TweakedPublicKey {
    type Err = secp256k1::Error;
    fn from_str(s: &str) -> Result<TweakedPublicKey, secp256k1::Error> {
        Ok(TweakedPublicKey(XOnlyPublicKey::from_str(s)?))
    }
}

/// A trait for tweaking Schnorr public keys
pub trait TapTweak {
    /// Tweaks an untweaked public key given an untweaked key and optional script tree merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked key
    ///  * P is the internal key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> (TweakedPublicKey, secp256k1::Parity);

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`]
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> TweakedPublicKey;
}

impl TapTweak for UntweakedPublicKey {
    fn tap_tweak<C: Verification>(self, secp: &Secp256k1<C>, merkle_root: Option<TapBranchHash>) -> (TweakedPublicKey, secp256k1::Parity) {
        let tweak_value = TapTweakHash::from_key_and_tweak(self, merkle_root).into_inner();
        let mut output_key = self.clone();
        let parity = output_key.tweak_add_assign(&secp, &tweak_value).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(&secp, &output_key, parity, tweak_value));
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}

impl TweakedPublicKey {
    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn into_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Returns a reference to underlying public key.
    pub fn as_inner(&self) -> &XOnlyPublicKey {
        &self.0
    }

    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORRSIG_PUBLIC_KEY_SIZE] {
        self.0.serialize()
    }
}

/// A BIP340-341 serialized schnorr signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SchnorrSig {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: SchnorrSigHashType,
}

impl SchnorrSig {

    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, SchnorrSigError> {
        match sl.len() {
            64 => {
                // default type
                let sig = secp256k1::schnorr::Signature::from_slice(sl)
                    .map_err(SchnorrSigError::Secp256k1)?;
                return Ok( SchnorrSig { sig, hash_ty : SchnorrSigHashType::Default });
            },
            65 => {
                let (hash_ty, sig) = sl.split_last().expect("Slice len checked == 65");
                let hash_ty = SchnorrSigHashType::from_u8(*hash_ty)
                    .map_err(|_| SchnorrSigError::InvalidSighashType(*hash_ty))?;
                let sig = secp256k1::schnorr::Signature::from_slice(sig)
                    .map_err(SchnorrSigError::Secp256k1)?;
                Ok(SchnorrSig { sig, hash_ty })
            }
            len => {
                Err(SchnorrSigError::InvalidSchnorrSigSize(len))
            }
        }
    }

    /// Serialize SchnorrSig
    pub fn to_vec(&self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if self.hash_ty == SchnorrSigHashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }

}

/// A schnorr sig related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSigError {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid schnorr signature size
    InvalidSchnorrSigSize(usize),
}


impl fmt::Display for SchnorrSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SchnorrSigError::InvalidSighashType(hash_ty) =>
                write!(f, "Invalid signature hash type {}", hash_ty),
            SchnorrSigError::Secp256k1(ref e) =>
                write!(f, "Schnorr Signature has correct len, but is malformed : {}", e),
            SchnorrSigError::InvalidSchnorrSigSize(sz) =>
                write!(f, "Invalid Schnorr signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl ::std::error::Error for SchnorrSigError {}

impl From<secp256k1::Error> for SchnorrSigError {

    fn from(e: secp256k1::Error) -> SchnorrSigError {
        SchnorrSigError::Secp256k1(e)
    }
}
