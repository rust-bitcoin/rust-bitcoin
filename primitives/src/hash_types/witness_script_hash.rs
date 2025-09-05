// SPDX-License-Identifier: CC0-1.0

//! The `WScriptHash` type.

use core::convert::Infallible;
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256;
#[cfg(feature = "hex")]
use hex::FromHex as _;

use crate::script::{WitnessScript, MAX_WITNESS_SCRIPT_SIZE};

const LEN: usize = 32;
#[cfg(feature = "hex")]
const REVERSE: bool = false;

/// SegWit (256-bit) version of a Bitcoin Script bytecode hash.
///
/// Note: there is another "script hash" object in bitcoin ecosystem (Electrum protocol) that
/// looks similar to this one also being SHA256, however, they hash semantically different
/// scripts and have reversed representations, so this type cannot be used for both.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WScriptHash(sha256::Hash);

type HashType = WScriptHash;

impl WScriptHash {
    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(sha256::Hash::from_byte_array(bytes))
    }

    /// Constructs a new `WScriptHash` after first checking the script size.
    ///
    /// # 10,000-byte limit on the witness script
    ///
    /// > The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the
    /// > witnessScript must match the 32-byte witness program.
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script(witness_script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        if witness_script.len() > MAX_WITNESS_SCRIPT_SIZE {
            return Err(WitnessScriptSizeError { size: witness_script.len() });
        }

        // We've just checked the length
        Ok(WScriptHash::from_script_unchecked(witness_script))
    }

    /// Constructs a new `WScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 10,000 bytes in size and use it to create a Segwit
    /// output then the output will be unspendable (see [BIP-141]).
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script_unchecked(script: &WitnessScript) -> Self {
        WScriptHash(sha256::Hash::hash(script.as_bytes()))
    }
}

/// Error while hashing a witness script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessScriptSizeError {
    /// Invalid witness script size (cannot exceed 10,000 bytes).
    size: usize,
}

impl WitnessScriptSizeError {
    /// Returns the invalid witness script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

impl From<Infallible> for WitnessScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for WitnessScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "witness script size exceeds {} bytes: {}", MAX_WITNESS_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessScriptSizeError {}

include!("./generic.rs");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for WScriptHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = u.arbitrary()?;
        let t = sha256::Hash::from_byte_array(arbitrary_bytes);
        Ok(WScriptHash(t))
    }
}
