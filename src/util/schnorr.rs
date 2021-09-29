// Rust Bitcoin Library
// Written in 2021 by
//     Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Schnorr Bitcoin Keys
//!
//! Schnorr keys used in Bitcoin, reexporting Secp256k1 Schnorr key types
//!

pub use secp256k1::schnorrsig::{PublicKey, KeyPair, Signature};

use core::fmt;
use core::str::FromStr;
use hashes::hex::{ToHex, FromHex};
use consensus::encode;
use SigHashType;

/// Signature-related data as they are used in `witness` and PSBT serialization
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpendingSignature {
    /// Signature, serializable according to BIP-340 rules
    signature: Signature,
    /// Sighash flag, serializable only if it is not SIGHASH_ALL
    sighash_type: SigHashType
}

impl fmt::Display for SpendingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.signature.to_hex())?;
        if self.requires_sighash() {
            write!(f, "{}", self.sighash_type as u8)?;
        }
        Ok(())
    }
}

impl FromStr for SpendingSignature {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)
            .map_err(|_| encode::Error::ParseFailed("spending signature string is not hex-encoded"))?;
        match bytes.len() {
            64 => Ok(SpendingSignature::sighash_all(
                Signature::from_slice(&bytes)
                    .expect("BIP-340 signature failure to deserialize from 64 byte slice"))
            ),
            65 => Ok(SpendingSignature {
                signature: Signature::from_slice(&bytes[..=64])
                    .expect("BIP-340 signature failure to deserialize from 64 byte slice"),
                sighash_type: SigHashType::from_u32_consensus(bytes[64] as u32)
            }),
            _ => Err(encode::Error::ParseFailed("incorrect length of serialized BIP-341 signature data")),
        }
    }
}

impl SpendingSignature {
    /// Constructs partial signature for [`SigHash::All`]
    #[inline]
    pub fn sighash_all(signature: Signature) -> SpendingSignature {
        SpendingSignature {
            signature,
            sighash_type: SigHashType::All
        }
    }

    /// Constrictor for the type if a custom sighash flag is used. In case of `SIGHASH_ALL` you can
    /// use [`SpendingSignature::sighash_all`]
    #[inline]
    pub fn with(signature: Signature, sighash_type: SigHashType) -> SpendingSignature {
        SpendingSignature {
            signature,
            sighash_type
        }
    }

    /// Getter method for accessing signature data
    #[inline]
    pub fn signature(self) -> Signature {
        self.signature
    }

    /// Getter method for accessing sighash flag
    #[inline]
    pub fn sighash_type(self) -> SigHashType {
        self.sighash_type
    }

    /// Getter method for sighash flag representation as consensus-serializable byte
    #[inline]
    pub fn sighash_byte(self) -> u8 {
        self.sighash_type as u8
    }

    /// Detects whether we need to serialize sighash flag after the signature
    #[inline]
    pub fn requires_sighash(&self) -> bool {
        self.sighash_type == SigHashType::All
    }
}

