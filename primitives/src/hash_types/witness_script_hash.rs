// SPDX-License-Identifier: CC0-1.0

//! The [`WScriptHash`] type.

#[cfg(feature = "alloc")]
use core::convert::Infallible;
#[cfg(any(feature = "alloc", feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256;

#[cfg(feature = "alloc")]
use crate::script::{PushBytes, PushBytesBuf, WitnessScript, MAX_WITNESS_SCRIPT_SIZE};

/// SegWit (256-bit) version of a Bitcoin Script bytecode hash.
///
/// Note: there is another "script hash" object in the Bitcoin ecosystem (Electrum protocol) that
/// looks similar to this one also being SHA256, however, they hash semantically different
/// scripts and have reversed representations, so this type cannot be used for both.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WScriptHash(sha256::Hash);

super::impl_debug!(WScriptHash);
#[cfg(feature = "alloc")]
crate::impl_asref_push_bytes!(WScriptHash);

#[cfg(feature = "alloc")]
impl WScriptHash {
    /// Constructs a new [`WScriptHash`] after first checking the script size.
    ///
    /// # 10,000-byte limit on the witness script
    ///
    /// > The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the
    /// > witnessScript must match the 32-byte witness program.
    ///
    /// ref: [BIP-0141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    ///
    /// # Errors
    ///
    /// Returns an error if the script exceeds 10,000 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::script::{ScriptPubKeyBuf, WScriptHash, WitnessScriptBuf};
    ///
    /// // Far too big for P2SH, but unremarkable for P2WSH.
    /// let witness_script = WitnessScriptBuf::from_bytes(vec![0x51; 1_000]);
    /// assert!(ScriptPubKeyBuf::new_p2wsh(witness_script.wscript_hash()?).is_p2wsh());
    ///
    /// let too_big = WitnessScriptBuf::from_bytes(vec![0x51; 10_001]);
    /// assert_eq!(too_big.wscript_hash().unwrap_err().invalid_size(), 10_001);
    /// # Ok::<_, bitcoin_primitives::script::WitnessScriptSizeError>(())
    /// ```
    #[inline]
    pub fn from_script(witness_script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        if witness_script.len() > MAX_WITNESS_SCRIPT_SIZE {
            return Err(WitnessScriptSizeError { size: witness_script.len() });
        }

        // We've just checked the length
        Ok(Self::from_script_unchecked(witness_script))
    }

    /// Constructs a new [`WScriptHash`] from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 10,000 bytes in size and use it to create a Segwit
    /// output then the output will be unspendable (see [BIP-0141]).
    ///
    /// ref: [BIP-0141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script_unchecked(script: &WitnessScript) -> Self {
        Self(sha256::Hash::hash(script.as_bytes()))
    }
}

/// Error while hashing a witness script.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessScriptSizeError {
    /// Invalid witness script size (cannot exceed 10,000 bytes).
    size: usize,
}

#[cfg(feature = "alloc")]
impl WitnessScriptSizeError {
    /// Returns the invalid witness script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

#[cfg(feature = "alloc")]
impl From<Infallible> for WitnessScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for WitnessScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "witness script size exceeds {} bytes: {}", MAX_WITNESS_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessScriptSizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { size: _ } = self;
        None
    }
}

include!("./generic.rs");

// The new hash wrapper type.
type HashType = WScriptHash;
// The inner hash type from `hashes`.
type Inner = sha256::Hash;
