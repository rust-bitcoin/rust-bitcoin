// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Consensus Encoding
//!
//! Traits and utilities for encoding and decoding Bitcoin data types in a consensus-consistent way,
//! using a *sans-I/O* architecture.
//!
//! Rather than reading from or writing to [`std::io::Read`]/[`std::io::Write`] traits directly, the
//! codec types work with byte slices. This keeps codec logic I/O-agnostic, so the same
//! implementation works in `no_std` environments, sync I/O, async I/O, and hash engines without
//! duplicating logic or surfacing I/O errors in non-I/O contexts (e.g. when hashing an encoding).
//!
//! *Consensus* encoding is the canonical byte representation of Bitcoin data types used across the
//! peer-to-peer network and transaction serialization. This crate only supports deterministic
//! encoding and will never support types like floats whose encoding is non-deterministic or
//! platform-dependent.
//!
//! # Encoding
//!
//! Types implement [`Encodable`] to produce an [`Encoder`], which yields encoded bytes in chunks
//! via [`Encoder::current_chunk`] and [`Encoder::advance`]. The caller drives the process by
//! pulling chunks until `advance` returns `false`.
//!
//! # Decoding
//!
//! Types implement [`Decodable`] to produce a [`Decoder`], which consumes bytes via
//! [`Decoder::push_bytes`] until it signals completion by returning `Ok(false)`. The caller then
//! calls [`Decoder::end`] to obtain the decoded value.
//!
//! Unlike encoding, decoding is fallible. Both `push_bytes` and `end` return `Result`. I/O errors
//! are handled by the caller, keeping the codec logic I/O-agnostic.
//!
//! # Drivers
//!
//! This crate provides free functions which drive codecs for common I/O interfaces. On the decoding
//! side we provide:
//!
//! * [`decode_from_read`]: Decode from a stblib buffered reader.
//! * [`decode_from_read_unbuffered`]: Decode from a stdlib unbuffered reader (4k buffer on stack).
//! * [`decode_from_read_unbuffered_with`]: As above with custom sized stack-allocated buffer.
//! * [`decode_from_slice`]: Decode from a byte slice (errors if slice is not completely consumed).
//! * [`decode_from_slice_unbounded`]: Slice can contain additional data after decoding completes.
//!
//! And on the encoding side we provide:
//!
//! * [`encode_to_writer`]: Encode to a stdlib writer.
//! * [`flush_to_writer`]: Flush an encoder to a stdlib writer.
//! * [`encode_to_vec`]: Encode to the heap.
//! * [`flush_to_vec`]: Flush an encoder to the heap.
//!
//! # Feature Flags
//!
//! * `std` - Enables std lib I/O driver functions and `std::error::Error` impls (implies `alloc`).
//! * `alloc` - Enables [`encode_to_vec`], `Vec`-based decoders, and allocation-based helpers.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(rust_v_1_65)]
mod compact_size;
#[cfg(rust_v_1_65)]
mod decode;
#[cfg(rust_v_1_65)]
mod encode;
#[cfg(rust_v_1_65)]
mod impls;

#[cfg(rust_v_1_65)]
pub mod error;

#[cfg(rust_v_1_65)]
#[doc(inline)]
pub use self::compact_size::{CompactSizeDecoder, CompactSizeEncoder, CompactSizeU64Decoder};
#[cfg(rust_v_1_65)]
#[doc(inline)]
pub use self::decode::decoders::{
    ArrayDecoder, Decoder2, Decoder3, Decoder4, Decoder6, MapDecoder,
};
#[cfg(all(feature = "alloc", rust_v_1_65))]
#[doc(inline)]
pub use self::decode::decoders::{ByteVecDecoder, VecDecoder};
#[cfg(all(feature = "std", rust_v_1_65))]
#[doc(inline)]
pub use self::decode::{
    decode_from_read, decode_from_read_unbuffered, decode_from_read_unbuffered_with,
};
#[cfg(rust_v_1_65)]
#[doc(inline)]
pub use self::decode::{decode_from_slice, decode_from_slice_unbounded, Decodable, Decoder};
#[cfg(rust_v_1_65)]
#[doc(inline)]
pub use self::encode::encoders::{
    ArrayEncoder, ArrayRefEncoder, BytesEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
    SliceEncoder,
};
#[cfg(all(feature = "alloc", rust_v_1_65))]
#[doc(inline)]
pub use self::encode::{encode_to_vec, flush_to_vec};
#[cfg(all(feature = "std", rust_v_1_65))]
#[doc(inline)]
pub use self::encode::{encode_to_writer, flush_to_writer};
#[cfg(rust_v_1_65)]
#[doc(inline)]
pub use self::encode::{Encodable, Encoder, EncoderByteIter, ExactSizeEncoder};
#[cfg(all(feature = "alloc", rust_v_1_65))]
#[doc(no_inline)]
pub use self::error::LengthPrefixExceedsMaxError;
#[cfg(all(feature = "std", rust_v_1_65))]
#[doc(no_inline)]
pub use self::error::ReadError;
#[cfg(all(feature = "alloc", rust_v_1_65))]
#[doc(no_inline)]
pub use self::error::{ByteVecDecoderError, VecDecoderError};
#[cfg(rust_v_1_65)]
#[doc(no_inline)]
pub use self::error::{
    CompactSizeDecoderError, DecodeError, Decoder2Error, Decoder3Error, Decoder4Error,
    Decoder6Error, UnconsumedError, UnexpectedEofError,
};
