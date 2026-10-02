// SPDX-License-Identifier: CC0-1.0

//! The [`ScriptHash`] type.

#[cfg(feature = "alloc")]
use core::convert::Infallible;
#[cfg(any(feature = "alloc", feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::hash160;
#[cfg(feature = "alloc")]
use internals::write_err;

#[cfg(feature = "alloc")]
use crate::script::{PushBytes, PushBytesBuf, Script, ScriptHashableTag, MAX_REDEEM_SCRIPT_SIZE};
#[cfg(feature = "alloc")]
use crate::witness_version::WitnessVersion;

/// A 160-bit hash of Bitcoin Script bytecode.
///
/// Note: there is another "script hash" object in the Bitcoin ecosystem (Electrum protocol) that
/// uses 256-bit hash and hashes a semantically different script. Thus, this type cannot
/// represent it.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptHash(hash160::Hash);

super::impl_debug!(ScriptHash);
#[cfg(feature = "alloc")]
crate::impl_asref_push_bytes!(ScriptHash);

#[cfg(feature = "alloc")]
impl ScriptHash {
    /// Constructs a new [`ScriptHash`] after first checking the script is safe to P2SH-wrap.
    ///
    /// # 520-byte limitation on serialized script size
    ///
    /// > As a consequence of the requirement for backwards compatibility the serialized script is
    /// > itself subject to the same rules as any other PUSHDATA operation, including the rule that
    /// > no data greater than 520 bytes may be pushed to the stack. Thus it is not possible to
    /// > spend a P2SH output if the redemption script it refers to is >520 bytes in length.
    ///
    /// ref: [BIP-0016](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size)
    ///
    /// # SegWit version 1+ witness programs
    ///
    /// Only SegWit version 0 witness programs may be P2SH-wrapped. A P2SH output wrapping a
    /// version 1 or higher witness program is not encumbered by it and can be spent by anyone
    /// (see [BIP-0341]).
    ///
    /// [BIP-0341]: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
    ///
    /// # Errors
    ///
    /// Returns an error if the script exceeds 520 bytes or is a SegWit version 1+ witness program.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin_primitives::script::{
    ///     RedeemScriptBuf, RedeemScriptError, ScriptHash, ScriptPubKeyBuf,
    /// };
    ///
    /// let redeem_script = RedeemScriptBuf::from_bytes(vec![0x51]);
    /// assert!(ScriptPubKeyBuf::new_p2sh(redeem_script.script_hash()?).is_p2sh());
    ///
    /// let too_big = RedeemScriptBuf::from_bytes(vec![0x51; 521]);
    /// match too_big.script_hash().unwrap_err() {
    ///     RedeemScriptError::Size(e) => assert_eq!(e.invalid_size(), 521),
    ///     _ => unreachable!(),
    /// }
    /// # Ok::<_, RedeemScriptError>(())
    /// ```
    #[inline]
    pub fn from_script<T>(redeem_script: &Script<T>) -> Result<Self, RedeemScriptError>
    where
        T: ScriptHashableTag,
    {
        if redeem_script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(RedeemScriptError::Size(RedeemScriptSizeError {
                size: redeem_script.len(),
            }));
        }
        match redeem_script.witness_version() {
            None | Some(WitnessVersion::V0) => {}
            Some(version) => return Err(RedeemScriptError::WitnessVersion(version)),
        }

        // We've just checked the script
        Ok(Self::from_script_unchecked(redeem_script))
    }

    /// Constructs a new [`ScriptHash`] from any script without any checks.
    ///
    /// If you hash a script that exceeds 520 bytes in size and use it to create a P2SH output
    /// then the output will be unspendable (see [BIP-0016]). If you hash a SegWit version 1+
    /// witness program and use it to create a P2SH output then anyone can spend it (see
    /// [BIP-0341]).
    ///
    /// [BIP-0016]: <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size>
    /// [BIP-0341]: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
    #[inline]
    pub fn from_script_unchecked<T>(script: &Script<T>) -> Self {
        Self(hash160::Hash::hash(script.as_bytes()))
    }
}

/// Error while hashing a redeem script.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedeemScriptError {
    /// The script exceeds 520 bytes.
    Size(RedeemScriptSizeError),
    /// The script is a SegWit version 1+ witness program, which cannot be P2SH-wrapped.
    WitnessVersion(WitnessVersion),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for RedeemScriptError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for RedeemScriptError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Size(ref e) => write_err!(f, "invalid redeem script"; e),
            Self::WitnessVersion(v) =>
                write!(f, "SegWit v{} witness program cannot be P2SH-wrapped", v),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RedeemScriptError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Size(e) => Some(e),
            Self::WitnessVersion(_) => None,
        }
    }
}

/// Error while hashing a redeem script that exceeds 520 bytes.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemScriptSizeError {
    /// Invalid redeem script size (cannot exceed 520 bytes).
    size: usize,
}

#[cfg(feature = "alloc")]
impl RedeemScriptSizeError {
    /// Returns the invalid redeem script size.
    #[inline]
    pub fn invalid_size(&self) -> usize { self.size }
}

#[cfg(feature = "alloc")]
impl From<Infallible> for RedeemScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for RedeemScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "redeem script size exceeds {} bytes: {}", MAX_REDEEM_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RedeemScriptSizeError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { size: _ } = self;
        None
    }
}

// The new hash wrapper type.
type HashType = ScriptHash;
// The inner hash type from `hashes`.
type Inner = hash160::Hash;

include!("./generic.rs");
