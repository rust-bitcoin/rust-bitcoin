// SPDX-License-Identifier: CC0-1.0

//! Compact size codec.
//!
//! Compact size is a variable-length integer encoding used throughout the Bitcoin
//! consensus protocol to encode collection lengths. However, there are also some
//! unique non-length use cases.

use internals::array_vec::ArrayVec;

use crate::decode::Decoder;
use crate::encode::{Encoder, ExactSizeEncoder};
use crate::error::{
    CompactSizeDecoderError, CompactSizeDecoderErrorInner, LengthPrefixExceedsMaxError,
};

/// Default maximum size of a decoded object in bytes.
///
/// Matches Bitcoin Core's default [serialization limit]. This is
/// a high level anti-DoS limit which all bitcoin types should
/// easily fit within.
///
/// [serialization limit]: https://github.com/bitcoin/bitcoin/blob/a7c29df0e5ace05b6186612671d6103c112ec922/src/serialize.h#L32
const MAX_COMPACT_SIZE: usize = 0x0200_0000;

/// The maximum length of a compact size encoding.
const SIZE: usize = 9;

/// Compact size prefix byte indicating a 2-byte `u16` payload follows.
const PREFIX_U16: u8 = 0xFD;
/// Compact size prefix byte indicating a 4-byte `u32` payload follows.
const PREFIX_U32: u8 = 0xFE;
/// Compact size prefix byte indicating an 8-byte `u64` payload follows.
const PREFIX_U64: u8 = 0xFF;

/// Encoder for a compact size encoded integer.
#[derive(Debug, Clone)]
pub struct CompactSizeEncoder {
    buf: Option<ArrayVec<u8, SIZE>>,
}

impl CompactSizeEncoder {
    /// Constructs a new `CompactSizeEncoder` for a length prefix.
    ///
    /// The `usize` type is the natural Rust type for lengths and collection sizes, which is the
    /// dominant use case for compact size encoding in the Bitcoin protocol. Prefer this constructor
    /// whenever you are encoding the length of a collection or a byte slice.
    ///
    /// Compact size encodings are defined only over the `u64` range. On exotic platforms where
    /// `usize` is wider than 64 bits the value will be saturated to [`u64::MAX`], but in practice
    /// any in-memory length that could actually be passed here is well within the `u64` range.
    ///
    /// If you need to encode an arbitrary `u64` integer that is not a length prefix, use
    /// [`Self::new_u64`] instead.
    pub fn new(value: usize) -> Self {
        Self { buf: Some(Self::encode(u64::try_from(value).unwrap_or(u64::MAX))) }
    }

    /// Constructs a new `CompactSizeEncoder` for an arbitrary `u64` integer.
    ///
    /// Prefer [`Self::new`] unless you are encoding a non-length integer.
    ///
    /// A small number of fields in the Bitcoin protocol are compact-size-encoded integers that are
    /// not collection lengths (e.g. service flags). Use this constructor for those cases, where the
    /// natural type of the value is `u64` rather than `usize`.
    pub fn new_u64(value: u64) -> Self { Self { buf: Some(Self::encode(value)) } }

    /// Returns the number of bytes used to encode this `CompactSize` value.
    ///
    /// # Returns
    ///
    /// - 1 for 0..=0xFC
    /// - 3 for 0xFD..=(2^16-1)
    /// - 5 for 0x10000..=(2^32-1)
    /// - 9 otherwise.
    #[inline]
    pub const fn encoded_size(value: usize) -> usize {
        match value {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }

    /// Encodes `CompactSize` without allocating.
    #[inline]
    fn encode(value: u64) -> ArrayVec<u8, SIZE> {
        let mut res = ArrayVec::<u8, SIZE>::new();
        match value {
            0..=0xFC => {
                res.push(value as u8); // Cast ok because of match.
            }
            0xFD..=0xFFFF => {
                let v = value as u16; // Cast ok because of match.
                res.push(PREFIX_U16);
                res.extend_from_slice(&v.to_le_bytes());
            }
            0x10000..=0xFFFF_FFFF => {
                let v = value as u32; // Cast ok because of match.
                res.push(PREFIX_U32);
                res.extend_from_slice(&v.to_le_bytes());
            }
            _ => {
                res.push(PREFIX_U64);
                res.extend_from_slice(&value.to_le_bytes());
            }
        }
        res
    }
}

impl Encoder for CompactSizeEncoder {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.buf.as_ref().map(|b| &b[..]).unwrap_or_default() }

    #[inline]
    fn advance(&mut self) -> bool {
        self.buf = None;
        false
    }
}

impl ExactSizeEncoder for CompactSizeEncoder {
    #[inline]
    fn len(&self) -> usize { self.buf.map_or(0, |buf| buf.len()) }
}

/// Decodes a compact size encoded integer as a length prefix.
///
/// The decoded value is returned as a `usize` and is bounded by a configurable limit (default:
/// 4,000,000). This limit is a denial-of-service protection: a malicious peer can send a compact
/// size value up to 2^64-1, and without a limit check the caller might attempt to allocate an
/// enormous buffer based on that value. [`CompactSizeDecoder`] prevents this by rejecting values
/// that exceed the limit before returning them to the caller.
///
/// If you are decoding an arbitrary `u64` integer that is genuinely not a length prefix, use
/// [`CompactSizeU64Decoder`] instead.
///
/// For more information about decoders see the documentation of the [`Decoder`] trait.
#[derive(Debug, Clone)]
pub struct CompactSizeDecoder {
    buf: ArrayVec<u8, 9>,
    limit: usize,
}

impl CompactSizeDecoder {
    /// Constructs a new compact size decoder with the default 32MB length limit.
    pub const fn new() -> Self { Self { buf: ArrayVec::new(), limit: MAX_COMPACT_SIZE } }

    /// Constructs a new compact size decoder with a custom length limit.
    ///
    /// The decoded value must not exceed `limit`, otherwise [`end`](Self::end) will return an
    /// error. Use this when you know the field you are decoding has a tighter bound than the
    /// default limit of 32MB.
    pub const fn new_with_limit(limit: usize) -> Self { Self { buf: ArrayVec::new(), limit } }
}

impl Default for CompactSizeDecoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for CompactSizeDecoder {
    type Output = usize;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(compact_size_push_bytes(&mut self.buf, bytes))
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use CompactSizeDecoderErrorInner as E;

        let dec_value = compact_size_decode_u64(&self.buf)?;

        // This error is returned if dec_value is outside of the usize range, or
        // if it is above the given limit.
        let make_err = || {
            CompactSizeDecoderError(E::ValueExceedsLimit(LengthPrefixExceedsMaxError {
                value: dec_value,
                limit: self.limit,
            }))
        };

        usize::try_from(dec_value).map_err(|_| make_err()).and_then(|nsize| {
            if nsize > self.limit {
                Err(make_err())
            } else {
                Ok(nsize)
            }
        })
    }

    fn read_limit(&self) -> usize { compact_size_read_limit(&self.buf) }
}

/// Decodes a compact size encoded integer as a raw `u64`.
///
/// If you are decoding a length prefix, you probably want [`CompactSizeDecoder`] instead.
///
/// This decoder performs no limit check and no conversion to `usize`. It exists for the small
/// number of Bitcoin protocol fields that are compact-size-encoded integers but are not length
/// prefixes (e.g. service flags in the `version` message). For those fields the full `u64` range is
/// meaningful and there is no associated allocation whose size would be controlled by the decoded
/// value.
///
/// # Denial-of-service warning
///
/// Do not use this decoder for length prefixes. If the decoded value is used to size an allocation,
/// for example as the length of a `Vec`, a malicious peer can send a compact size value of up to
/// 2^64-1 and cause an out-of-memory condition. [`CompactSizeDecoder`] prevents this by enforcing a
/// configurable upper bound before returning the value.
///
/// For more information about decoders see the documentation of the [`Decoder`] trait.
#[derive(Debug, Clone)]
pub struct CompactSizeU64Decoder {
    buf: ArrayVec<u8, 9>,
}

impl CompactSizeU64Decoder {
    /// Constructs a new `CompactSizeU64Decoder`.
    ///
    /// See the [struct-level documentation](Self) for guidance on when to use this decoder versus
    /// [`CompactSizeDecoder`].
    pub const fn new() -> Self { Self { buf: ArrayVec::new() } }
}

impl Default for CompactSizeU64Decoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for CompactSizeU64Decoder {
    type Output = u64;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(compact_size_push_bytes(&mut self.buf, bytes))
    }

    fn end(self) -> Result<Self::Output, Self::Error> { compact_size_decode_u64(&self.buf) }

    fn read_limit(&self) -> usize { compact_size_read_limit(&self.buf) }
}

/// Pushes bytes into a compact size buffer, returning true if more bytes are needed.
fn compact_size_push_bytes(buf: &mut ArrayVec<u8, 9>, bytes: &mut &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }

    if buf.is_empty() {
        buf.push(bytes[0]);
        *bytes = &bytes[1..];
    }
    let len = match buf[0] {
        PREFIX_U64 => 9,
        PREFIX_U32 => 5,
        PREFIX_U16 => 3,
        _ => 1,
    };
    let to_copy = bytes.len().min(len - buf.len());
    buf.extend_from_slice(&bytes[..to_copy]);
    *bytes = &bytes[to_copy..];

    buf.len() != len
}

/// Returns the number of bytes the compact size decoder still needs to read.
fn compact_size_read_limit(buf: &ArrayVec<u8, 9>) -> usize {
    match buf.len() {
        0 => 1,
        already_read => match buf[0] {
            PREFIX_U64 => 9_usize.saturating_sub(already_read),
            PREFIX_U32 => 5_usize.saturating_sub(already_read),
            PREFIX_U16 => 3_usize.saturating_sub(already_read),
            _ => 0,
        },
    }
}

/// Decodes a compact size buffer to a u64, checking for minimal encoding.
fn compact_size_decode_u64(buf: &ArrayVec<u8, 9>) -> Result<u64, CompactSizeDecoderError> {
    use CompactSizeDecoderErrorInner as E;

    fn arr<const N: usize>(slice: &[u8]) -> Result<[u8; N], CompactSizeDecoderError> {
        slice.try_into().map_err(|_| {
            CompactSizeDecoderError(E::UnexpectedEof { required: N, received: slice.len() })
        })
    }

    let (first, payload) = buf
        .split_first()
        .ok_or(CompactSizeDecoderError(E::UnexpectedEof { required: 1, received: 0 }))?;

    match *first {
        PREFIX_U64 => {
            let x = u64::from_le_bytes(arr(payload)?);
            if x < 0x100_000_000 {
                Err(CompactSizeDecoderError(E::NonMinimal { value: x }))
            } else {
                Ok(x)
            }
        }
        PREFIX_U32 => {
            let x = u32::from_le_bytes(arr(payload)?);
            if x < 0x10000 {
                Err(CompactSizeDecoderError(E::NonMinimal { value: x.into() }))
            } else {
                Ok(x.into())
            }
        }
        PREFIX_U16 => {
            let x = u16::from_le_bytes(arr(payload)?);
            if x < 0xFD {
                Err(CompactSizeDecoderError(E::NonMinimal { value: x.into() }))
            } else {
                Ok(x.into())
            }
        }
        n => Ok(n.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_value_1_byte() {
        // Check lower bound, upper bound (and implicitly endian-ness).
        for v in [0x00u64, 0x01, 0x02, 0xFA, 0xFB, 0xFC] {
            assert_eq!(CompactSizeEncoder::encoded_size(v as usize), 1);
            // Should be encoded as the value as a u8.
            let want = [v as u8];
            let got = CompactSizeEncoder::encode(v);
            assert_eq!(got.as_slice().len(), 1); // sanity check
            assert_eq!(got.as_slice(), want);
        }
    }

    macro_rules! check_encode {
        ($($test_name:ident, $size:expr, $value:expr, $want:expr);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let value = $value as u64; // Because default integer type is i32.
                    assert_eq!(CompactSizeEncoder::encoded_size(value as usize), $size);
                    let got = CompactSizeEncoder::encode(value);
                    assert_eq!(got.as_slice().len(), $size); // sanity check
                    assert_eq!(got.as_slice(), &$want);
                }
            )*
        }
    }

    check_encode! {
        // 3 byte encoding.
        encoded_value_3_byte_lower_bound, 3, 0xFD, [0xFD, 0xFD, 0x00]; // 0x00FD
        encoded_value_3_byte_endianness, 3, 0xABCD, [0xFD, 0xCD, 0xAB];
        encoded_value_3_byte_upper_bound, 3, 0xFFFF, [0xFD, 0xFF, 0xFF];
        // 5 byte encoding.
        encoded_value_5_byte_lower_bound, 5, 0x0001_0000, [0xFE, 0x00, 0x00, 0x01, 0x00];
        encoded_value_5_byte_endianness, 5, 0x0123_4567, [0xFE, 0x67, 0x45, 0x23, 0x01];
        encoded_value_5_byte_upper_bound, 5, 0xFFFF_FFFF, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF];
    }

    // 9-byte encoding requires values above u32::MAX which don't fit in usize on 32-bit platforms.
    #[cfg(target_pointer_width = "64")]
    check_encode! {
        encoded_value_9_byte_lower_bound, 9, 0x0000_0001_0000_0000u64, [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        encoded_value_9_byte_endianness, 9, 0x0123_4567_89AB_CDEFu64, [0xFF, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        encoded_value_9_byte_upper_bound, 9, u64::MAX, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    }

    #[test]
    fn compact_size_new_values_too_large() {
        use CompactSizeDecoderErrorInner as E;

        const EXCESS_COMPACT_SIZE: u64 = (MAX_COMPACT_SIZE + 1) as u64;

        // MAX_COMPACT_SIZE should succeed for `new` constructor
        // 0x0200_0000 as minimal 5-byte compact size: 0xFE + u32 little-endian
        let mut decoder = CompactSizeDecoder::new();
        decoder.push_bytes(&mut [0xFE, 0x00, 0x00, 0x00, 0x02].as_slice()).unwrap();
        let got = decoder.end().unwrap();
        assert_eq!(got, MAX_COMPACT_SIZE);

        // MAX_COMPACT_SIZE + 1 should fail for `new` constructor
        // 0x0200_0001 as minimal 5-byte compact size: 0xFE + u32 little-endian
        let mut decoder = CompactSizeDecoder::new();
        decoder.push_bytes(&mut [0xFE, 0x01, 0x00, 0x00, 0x02].as_slice()).unwrap();
        let got = decoder.end().unwrap_err();
        assert!(matches!(
            got,
            CompactSizeDecoderError(E::ValueExceedsLimit(LengthPrefixExceedsMaxError {
                limit: MAX_COMPACT_SIZE,
                value: EXCESS_COMPACT_SIZE,
            })),
        ));
    }

    #[test]
    fn compact_size_new_with_limit_values_too_large() {
        use CompactSizeDecoderErrorInner as E;

        // 240 should succeed for `new_with_limit` constructor
        let mut decoder = CompactSizeDecoder::new_with_limit(240);
        decoder.push_bytes(&mut [0xf0].as_slice()).unwrap();
        let got = decoder.end().unwrap();
        assert_eq!(got, 240);

        // 241 should fail for `new_with_limit` constructor
        let mut decoder = CompactSizeDecoder::new_with_limit(240);
        decoder.push_bytes(&mut [0xf1].as_slice()).unwrap();
        let got = decoder.end().unwrap_err();
        assert!(matches!(
            got,
            CompactSizeDecoderError(E::ValueExceedsLimit(LengthPrefixExceedsMaxError {
                limit: 240,
                value: 241,
            })),
        ));
    }
}
