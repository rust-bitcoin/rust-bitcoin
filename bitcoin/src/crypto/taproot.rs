// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin taproot keys.
//!
//! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
//!

use core::fmt;

use bitcoin_internals::write_err;

pub use secp256k1::{self, constants, Secp256k1, KeyPair, XOnlyPublicKey, Verification, Parity};

use crate::prelude::*;

use crate::sighash::TapSighashType;

/// A BIP340-341 serialized taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: TapSighashType,
}

impl Signature {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        match sl.len() {
            64 => {
                // default type
                let sig = secp256k1::schnorr::Signature::from_slice(sl)
                    .map_err(Error::Secp256k1)?;
                Ok(Signature { sig, hash_ty: TapSighashType::Default })
            },
            65 => {
                let (hash_ty, sig) = sl.split_last().expect("Slice len checked == 65");
                let hash_ty = TapSighashType::from_consensus_u8(*hash_ty)
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
        if self.hash_ty == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }

}

/// A taproot sig related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid taproot signature size
    InvalidSignatureSize(usize),
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidSighashType(hash_ty) =>
                write!(f, "invalid signature hash type {}", hash_ty),
            Error::Secp256k1(ref e) =>
                write_err!(f, "taproot signature has correct len but is malformed"; e),
            Error::InvalidSignatureSize(sz) =>
                write!(f, "invalid taproot signature size: {}", sz),
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
