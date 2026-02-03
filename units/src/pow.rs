// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

#[cfg(feature = "encoding")]
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "encoding")]
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::parse_int::{self, PrefixedHexError, UnprefixedHexError};

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in bitcoin, which
/// is exactly this format.
///
/// # Note on order/equality
///
/// Usage of the ordering and equality traits for this type may be surprising. Converting between
/// `CompactTarget` and `Target` is lossy *in both directions* (there are multiple `CompactTarget`
/// values that map to the same `Target` value). Ordering and equality for this type are defined in
/// terms of the underlying `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Constructs a new [`CompactTarget`] from a consensus encoded `u32`.
    #[inline]
    pub fn from_consensus(bits: u32) -> Self { Self(bits) }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    #[inline]
    pub const fn to_consensus(self) -> u32 { self.0 }

    /// Gets the hex representation of this [`CompactTarget`].
    #[cfg(feature = "alloc")]
    #[inline]
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(self) -> alloc::string::String { alloc::format!("{:x}", self) }

    /// Constructs a new `CompactTarget` from a prefixed hex string.
    ///
    /// # Errors
    ///
    /// - If the input string does not contain a `0x` (or `0X`) prefix.
    /// - If the input string is not a valid hex encoding of a `u32`.
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError>
    where
        Self: Sized,
    {
        let target = parse_int::hex_u32_prefixed(s)?;
        Ok(Self::from_consensus(target))
    }

    /// Constructs a new `CompactTarget` from an unprefixed hex string.
    ///
    /// # Errors
    ///
    /// - If the input string contains a `0x` (or `0X`) prefix.
    /// - If the input string is not a valid hex encoding of a `u32`.
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError>
    where
        Self: Sized,
    {
        let target = parse_int::hex_u32_unprefixed(s)?;
        Ok(Self::from_consensus(target))
    }
}

impl fmt::Display for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::LowerHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Octal for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Octal::fmt(&self.0, f) }
}

impl fmt::Binary for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Binary::fmt(&self.0, f) }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`CompactTarget`] type.
    pub struct CompactTargetEncoder<'e>(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for CompactTarget {
    type Encoder<'e> = CompactTargetEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        CompactTargetEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`CompactTarget`] type.
#[cfg(feature = "encoding")]
pub struct CompactTargetDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl CompactTargetDecoder {
    /// Constructs a new [`CompactTarget`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl Default for CompactTargetDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for CompactTargetDecoder {
    type Output = CompactTarget;
    type Error = CompactTargetDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(CompactTargetDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end().map_err(CompactTargetDecoderError)?);
        Ok(CompactTarget::from_consensus(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for CompactTarget {
    type Decoder = CompactTargetDecoder;
    fn decoder() -> Self::Decoder { CompactTargetDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `CompactTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "encoding")]
pub struct CompactTargetDecoderError(encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for CompactTargetDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for CompactTargetDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "encoding")]
impl std::error::Error for CompactTargetDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CompactTarget {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_consensus(u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "std")]
    use std::error::Error as _;

    #[cfg(feature = "encoding")]
    use encoding::Decoder as _;

    use super::*;

    #[test]
    #[cfg(feature = "encoding")]
    fn compact_target_decoder_read_limit() {
        // read_limit is one u32 = 4 bytes for empty decoder
        assert_eq!(CompactTargetDecoder::default().read_limit(), 4);
        assert_eq!(<CompactTarget as encoding::Decodable>::decoder().read_limit(), 4);
    }

    #[test]
    #[cfg(feature = "encoding")]
    fn compact_target_decoder_round_trip() {
        let bits: u32 = 0x1d00_ffff;
        let compact_target =
            encoding::decode_from_slice::<CompactTarget>(&bits.to_le_bytes()).unwrap();
        assert_eq!(compact_target.to_consensus(), bits);
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(deprecated)]
    fn compact_target_to_hex() {
        let compact_target = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(compact_target.to_hex(), "1d00ffff");
    }

    #[test]
    #[cfg(feature = "encoding")]
    #[cfg(feature = "alloc")]
    fn compact_target_decoder_error_display_and_source() {
        let mut slice = [0u8; 3].as_slice();
        let mut decoder = CompactTargetDecoder::new();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }

    #[test]
    fn compact_target_ordering() {
        let lower = CompactTarget::from_consensus(0x1d00_fffe);
        let lower_copy = CompactTarget::from_consensus(0x1d00_fffe);
        let higher = CompactTarget::from_consensus(0x1d00_ffff);

        assert!(lower < higher);
        assert!(lower == lower_copy);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_target_formatting() {
        let compact_target = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(format!("{}", compact_target), "486604799");
        assert_eq!(format!("{:x}", compact_target), "1d00ffff");
        assert_eq!(format!("{:#x}", compact_target), "0x1d00ffff");
        assert_eq!(format!("{:X}", compact_target), "1D00FFFF");
        assert_eq!(format!("{:#X}", compact_target), "0x1D00FFFF");
        assert_eq!(format!("{:o}", compact_target), "3500177777");
        assert_eq!(format!("{:#o}", compact_target), "0o3500177777");
        assert_eq!(format!("{:b}", compact_target), "11101000000001111111111111111");
        assert_eq!(format!("{:#b}", compact_target), "0b11101000000001111111111111111");
        assert_eq!(compact_target.to_consensus(), 0x1d00_ffff);
    }

    #[test]
    fn compact_target_from_hex_lower() {
        let target = CompactTarget::from_hex("0x010034ab").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_hex_upper() {
        let target = CompactTarget::from_hex("0X010034AB").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_unprefixed_hex_lower() {
        let target = CompactTarget::from_unprefixed_hex("010034ab").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_unprefixed_hex_upper() {
        let target = CompactTarget::from_unprefixed_hex("010034AB").unwrap();
        assert_eq!(target, CompactTarget::from_consensus(0x0100_34ab));
    }

    #[test]
    fn compact_target_from_hex_invalid_hex_should_err() {
        let hex = "0xzbf9";
        let result = CompactTarget::from_hex(hex);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn compact_target_lower_hex_and_upper_hex() {
        assert_eq!(format!("{:08x}", CompactTarget::from_consensus(0x01D0_F456)), "01d0f456");
        assert_eq!(format!("{:08X}", CompactTarget::from_consensus(0x01d0_f456)), "01D0F456");
    }
}
