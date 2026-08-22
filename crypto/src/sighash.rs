// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed according to
//! [BIP-0341], [BIP-0143] and legacy (before BIP-0143).
//!
//! [BIP-0341]: <https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki>
//! [BIP-0143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>

use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

#[doc(no_inline)]
pub use self::error::{
    InvalidSighashTypeError, NonStandardSighashTypeError, SighashTypeParseError,
};

/// Hashtype of an input's signature, encoded in the last byte of the signature.
/// Fixed values so they can be cast as integer types for encoding.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TapSighashType {
    /// 0x0: Used when not explicitly specified, defaults to [`TapSighashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(TapSighashType, "a TapSighashType data");

impl fmt::Display for TapSighashType {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Default => "SIGHASH_DEFAULT",
            Self::All => "SIGHASH_ALL",
            Self::None => "SIGHASH_NONE",
            Self::Single => "SIGHASH_SINGLE",
            Self::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            Self::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            Self::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for TapSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_DEFAULT" => Ok(Self::Default),
            "SIGHASH_ALL" => Ok(Self::All),
            "SIGHASH_NONE" => Ok(Self::None),
            "SIGHASH_SINGLE" => Ok(Self::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(Self::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(Self::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(Self::SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.into() }),
        }
    }
}

impl TapSighashType {
    /// Constructs a new [`TapSighashType`] from a raw `u8`.
    ///
    /// # Errors
    ///
    /// This method fails if the provided sighash type is not valid.
    #[inline]
    pub fn from_consensus_u8(sighash_type: u8) -> Result<Self, InvalidSighashTypeError> {
        Ok(match sighash_type {
            0x00 => Self::Default,
            0x01 => Self::All,
            0x02 => Self::None,
            0x03 => Self::Single,
            0x81 => Self::AllPlusAnyoneCanPay,
            0x82 => Self::NonePlusAnyoneCanPay,
            0x83 => Self::SinglePlusAnyoneCanPay,
            x => return Err(InvalidSighashTypeError(x.into())),
        })
    }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
#[derive(Copy, Clone, Debug)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay,
    /// Any other value: consensus-valid but non-standard
    ///
    /// The value is a `u32` because the legacy and segwit v0 signing algorithms hash the
    /// sighash type as 4 bytes, even though only the lowest byte is appended to the
    /// signature in a transaction. On bitcoin the higher bits are always zero, but on replay-protected forks they are
    /// sometimes set.
    NonStandard(u32),
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl PartialEq for EcdsaSighashType {
    #[inline]
    fn eq(&self, other: &Self) -> bool { self.to_u32() == other.to_u32() }
}

impl Eq for EcdsaSighashType {}

impl PartialOrd for EcdsaSighashType {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for EcdsaSighashType {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering { self.to_u32().cmp(&other.to_u32()) }
}

impl core::hash::Hash for EcdsaSighashType {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.to_u32(), state);
    }
}

impl fmt::Display for EcdsaSighashType {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::All => "SIGHASH_ALL",
            Self::None => "SIGHASH_NONE",
            Self::Single => "SIGHASH_SINGLE",
            Self::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            Self::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            Self::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
            Self::NonStandard(n) => return write!(f, "0x{:02x}", n),
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_ALL" => Ok(Self::All),
            "SIGHASH_NONE" => Ok(Self::None),
            "SIGHASH_SINGLE" => Ok(Self::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(Self::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(Self::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(Self::SinglePlusAnyoneCanPay),
            _ => {
                // Non Standard values are displayed as "0xNN"
                // We return `Self::from_consensus(n)` instead of `Self::NonStandard(n)` so that
                // standard bytes map to the named variants (eg. 0x01 return `All`)
                if let Some(hex) = s.strip_prefix("0x") {
                    if let Ok(n) = u32::from_str_radix(hex, 16) {
                        return Ok(Self::from_consensus(n));
                    }
                }
                Err(SighashTypeParseError { unrecognized: s.into() })
            }
        }
    }
}

impl EcdsaSighashType {
    /// Checks if the sighash type is [`Self::Single`] or [`Self::SinglePlusAnyoneCanPay`].
    ///
    /// This matches Bitcoin Core's behavior where `SIGHASH_SINGLE` bug check is based on the base
    /// type (after masking with 0x1f), regardless of the ANYONECANPAY flag.
    ///
    /// See: <https://github.com/bitcoin/bitcoin/blob/e486597/src/script/interpreter.cpp#L1618-L1619>
    #[inline]
    pub fn is_single(&self) -> bool {
        match *self {
            Self::Single => true,
            Self::SinglePlusAnyoneCanPay => true,
            Self::NonStandard(n) => (n & 0x1f) == 0x03,
            _ => false,
        }
    }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// This round-trips: `from_consensus(n).to_u32() == n` for every `n`.
    ///
    /// **Note**: this replicates consensus behavior, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    #[inline]
    pub fn from_consensus(n: u32) -> Self {
        match n {
            // "real" sighashes
            0x01 => Self::All,
            0x02 => Self::None,
            0x03 => Self::Single,
            0x81 => Self::AllPlusAnyoneCanPay,
            0x82 => Self::NonePlusAnyoneCanPay,
            0x83 => Self::SinglePlusAnyoneCanPay,
            other => Self::NonStandard(other),
        }
    }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    #[inline]
    pub fn from_standard(n: u32) -> Result<Self, NonStandardSighashTypeError> {
        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(Self::All),
            0x02 => Ok(Self::None),
            0x03 => Ok(Self::Single),
            0x81 => Ok(Self::AllPlusAnyoneCanPay),
            0x82 => Ok(Self::NonePlusAnyoneCanPay),
            0x83 => Ok(Self::SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    #[inline]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllPlusAnyoneCanPay => 0x81,
            Self::NonePlusAnyoneCanPay => 0x82,
            Self::SinglePlusAnyoneCanPay => 0x83,
            Self::NonStandard(n) => n,
        }
    }

    /// Converts [`EcdsaSighashType`] to the `u8` appended to a signature.
    ///
    /// Only the lowest byte of the sighash type is appended to the signature, so we truncate
    /// to the lowest 8 bits.
    #[inline]
    pub fn to_consensus_u8(self) -> u8 { self.to_u32() as u8 }
}

impl TryFrom<EcdsaSighashType> for TapSighashType {
    type Error = InvalidSighashTypeError;

    #[inline]
    fn try_from(s: EcdsaSighashType) -> Result<Self, Self::Error> {
        match s {
            EcdsaSighashType::All => Ok(Self::All),
            EcdsaSighashType::None => Ok(Self::None),
            EcdsaSighashType::Single => Ok(Self::Single),
            EcdsaSighashType::AllPlusAnyoneCanPay => Ok(Self::AllPlusAnyoneCanPay),
            EcdsaSighashType::NonePlusAnyoneCanPay => Ok(Self::NonePlusAnyoneCanPay),
            EcdsaSighashType::SinglePlusAnyoneCanPay => Ok(Self::SinglePlusAnyoneCanPay),
            // Taproot doesnt accept non-standard sighash
            EcdsaSighashType::NonStandard(n) => Err(InvalidSighashTypeError(n)),
        }
    }
}

/// Error types for signature hashing.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::error::InputString;

    /// Integer is not a consensus valid sighash type.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InvalidSighashTypeError(pub(crate) u32);

    impl From<Infallible> for InvalidSighashTypeError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for InvalidSighashTypeError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "invalid sighash type {}", self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InvalidSighashTypeError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self(_) = self;
            None
        }
    }

    /// This type is consensus valid but an input including it would prevent the transaction from
    /// being relayed on today's Bitcoin network.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NonStandardSighashTypeError(pub(crate) u32);

    impl From<Infallible> for NonStandardSighashTypeError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for NonStandardSighashTypeError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "non-standard sighash type {}", self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for NonStandardSighashTypeError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self(_) = self;
            None
        }
    }

    /// Error returned for failure during parsing one of the sighash types.
    ///
    /// This is currently returned for unrecognized sighash strings.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct SighashTypeParseError {
        /// The unrecognized string we attempted to parse.
        pub(super) unrecognized: InputString,
    }

    impl From<Infallible> for SighashTypeParseError {
        #[inline]
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for SighashTypeParseError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.unrecognized.display_cannot_parse("SIGHASH string"))
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for SighashTypeParseError {
        #[inline]
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self { unrecognized: _ } = self;
            None
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EcdsaSighashType {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(Self::All),
            1 => Ok(Self::None),
            2 => Ok(Self::Single),
            3 => Ok(Self::AllPlusAnyoneCanPay),
            4 => Ok(Self::NonePlusAnyoneCanPay),
            _ => Ok(Self::SinglePlusAnyoneCanPay),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TapSighashType {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=6)?;
        match choice {
            0 => Ok(Self::Default),
            1 => Ok(Self::All),
            2 => Ok(Self::None),
            3 => Ok(Self::Single),
            4 => Ok(Self::AllPlusAnyoneCanPay),
            5 => Ok(Self::NonePlusAnyoneCanPay),
            _ => Ok(Self::SinglePlusAnyoneCanPay),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::{format, string::ToString};

    #[cfg(feature = "alloc")]
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn tapsighashtype_fromstr_display() {
        let sighashtypes = [
            ("SIGHASH_DEFAULT", TapSighashType::Default),
            ("SIGHASH_ALL", TapSighashType::All),
            ("SIGHASH_NONE", TapSighashType::None),
            ("SIGHASH_SINGLE", TapSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", TapSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", TapSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", TapSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(s.parse::<TapSighashType>().unwrap(), sht);
        }
        let sht_mistakes = [
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "DEFAULT",
            "ALL",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                s.parse::<TapSighashType>().unwrap_err().to_string(),
                format!("failed to parse '{}' as SIGHASH string", s)
            );
        }
    }

    #[test]
    fn ecdsa_sighash_type_from_consensus_roundtrips() {
        use super::EcdsaSighashType;

        for n in 0..=255u32 {
            let ty = EcdsaSighashType::from_consensus(n);
            assert_eq!(ty.to_u32(), n);
            assert_eq!(u32::from(ty.to_consensus_u8()), n);
            match n {
                0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83 =>
                    assert!(!matches!(ty, EcdsaSighashType::NonStandard(_))),
                _ => assert_eq!(ty, EcdsaSighashType::NonStandard(n)),
            }
        }

        // On replay-protected forks bits above the lowest byte are sometimes set.
        let ty = EcdsaSighashType::from_consensus(0x0100_0041);
        assert_eq!(ty, EcdsaSighashType::NonStandard(0x0100_0041));
        assert_eq!(ty.to_u32(), 0x0100_0041);

        assert_eq!(ty.to_consensus_u8(), 0x41);
    }

    #[test]
    fn ecdsa_sighash_type_non_standard_is_single_uses_mask() {
        use super::EcdsaSighashType;

        assert!(EcdsaSighashType::NonStandard(0x63).is_single());
        assert!(EcdsaSighashType::NonStandard(0xe3).is_single());
        assert!(!EcdsaSighashType::NonStandard(0x65).is_single());
        assert!(!EcdsaSighashType::NonStandard(0x62).is_single());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn ecdsasighashtype_fromstr_display() {
        let sighashtypes = [
            ("SIGHASH_ALL", EcdsaSighashType::All),
            ("SIGHASH_NONE", EcdsaSighashType::None),
            ("SIGHASH_SINGLE", EcdsaSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", EcdsaSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", EcdsaSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", EcdsaSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(s.parse::<EcdsaSighashType>().unwrap(), sht);
        }
        let sht_mistakes = [
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                s.parse::<EcdsaSighashType>().unwrap_err().to_string(),
                format!("failed to parse '{}' as SIGHASH string", s)
            );
        }
    }
}
