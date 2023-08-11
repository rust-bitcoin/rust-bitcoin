// SPDX-License-Identifier: CC0-1.0

//! Segwit v0 ECDSA Bitcoin signatures.

use core::fmt;
use core::str::FromStr;

use secp256k1;

#[cfg(doc)]
use crate::crypto::ecdsa::EcdsaSighashType;
use crate::crypto::ecdsa::{self, Error, SerializedSignature};
use crate::prelude::*;

/// A segwit v0 Bitcoin ECDSA signature.
///
/// This is just a thin wrapper around [`ecdsa::Signature`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature(pub(crate) ecdsa::Signature);

impl Signature {
    /// Construct a segwit v0 ECDSA Bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(sig: secp256k1::ecdsa::Signature) -> Signature {
        Self(ecdsa::Signature::sighash_all(sig))
    }

    /// Deserializes from slice following the standardness rules for [`EcdsaSighashType`].
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        Ok(Self(ecdsa::Signature::from_slice(sl)?))
    }

    /// Serializes a segwit v0 ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    pub fn serialize(&self) -> SerializedSignature { self.0.serialize() }

    /// Serializes a segwit v0 ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    ///
    /// Note: this performs an extra heap allocation, you might prefer the
    /// [`serialize`](Self::serialize) method instead.
    pub fn to_vec(self) -> Vec<u8> { self.0.to_vec() }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(Self(ecdsa::Signature::from_str(s)?)) }
}
