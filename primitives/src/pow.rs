// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

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
}

impl fmt::LowerHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`CompactTarget`] type.
    pub struct CompactTargetEncoder<'e>(encoding::ArrayEncoder<4>);
}

impl encoding::Encodable for CompactTarget {
    type Encoder<'e> = CompactTargetEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        CompactTargetEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_consensus().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`CompactTarget`] type.
pub struct CompactTargetDecoder(encoding::ArrayDecoder<4>);

impl CompactTargetDecoder {
    /// Constructs a new [`CompactTarget`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for CompactTargetDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for CompactTargetDecoder {
    type Output = CompactTarget;
    type Error = CompactTargetDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end()?);
        Ok(CompactTarget::from_consensus(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for CompactTarget {
    type Decoder = CompactTargetDecoder;
    fn decoder() -> Self::Decoder { CompactTargetDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `CompactTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactTargetDecoderError(encoding::UnexpectedEofError);

impl From<Infallible> for CompactTargetDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<encoding::UnexpectedEofError> for CompactTargetDecoderError {
    fn from(e: encoding::UnexpectedEofError) -> Self { Self(e) }
}

impl fmt::Display for CompactTargetDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "sequence decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompactTargetDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;
    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "std")]
    use std::error::Error as _;

    use encoding::Decoder as _;

    use super::*;

    #[test]
    fn compact_target_decoder_read_limit() {
        // read_limit is one u32 = 4 bytes for empty decoder
        assert_eq!(CompactTargetDecoder::default().read_limit(), 4);
        assert_eq!(<CompactTarget as encoding::Decodable>::decoder().read_limit(), 4);
    }

    #[test]
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
        assert_eq!(format!("{:x}", compact_target), "1d00ffff");
        assert_eq!(format!("{:X}", compact_target), "1D00FFFF");
        assert_eq!(compact_target.to_consensus(), 0x1d00_ffff);
    }
}
