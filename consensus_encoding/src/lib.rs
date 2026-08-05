// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Consensus Encoding
//!
//! Traits and utilities for encoding and decoding Bitcoin data types using a *sans-I/O*
//! architecture.
//!
//! Rather than reading from or writing to [`std::io::Read`]/[`std::io::Write`] traits directly, the
//! codec types work with byte slices. This keeps codec logic I/O-agnostic, so the same
//! implementation works in `no_std` environments, sync I/O, async I/O, and hash engines without
//! duplicating logic or surfacing I/O errors in non-I/O contexts (e.g. when hashing an encoding).
//! This crate only supports deterministic encoding and will never support types like floats whose
//! encoding is non-deterministic or platform-dependent.
//!
//! *Consensus* encoding is the canonical byte representation of Bitcoin data types used across the
//! peer-to-peer network and transaction serialization. Bitcoin types which support consensus
//! encoding implement the [`Encode`] and [`Decode`] traits.
//!
//! # Encoding
//!
//! Consensus encodable types implement [`Encode`] to produce an [`Encoder`], which yields encoded
//! bytes in chunks via [`Encoder::current_chunk`] and [`Encoder::advance`]. The caller drives the
//! process by pulling chunks until `advance` returns [`EncoderStatus::Finished`].
//!
//! # Decoding
//!
//! Consensus encodable types implement [`Decode`] to produce a [`Decoder`], which consumes bytes
//! via [`Decoder::push_bytes`] until it signals completion by returning `Ok(DecoderStatus::Ready)`.
//! The caller then calls [`Decoder::end`] to obtain the decoded value.
//!
//! Unlike encoding, decoding is fallible. Both `push_bytes` and `end` return `Result`. I/O errors
//! are handled by the caller, keeping the codec logic I/O-agnostic.
//!
//! # Drivers
//!
//! This crate provides free functions which drive codecs for common I/O interfaces. On the decoding
//! side we provide functions which take a consensus encodable type parameter `T: Decode` to select
//! the output type's associated decoder.
//!
//! * [`decode_from_read`]: Decode from a stdlib buffered reader.
//! * [`decode_from_read_unbuffered`]: Decode from a stdlib unbuffered reader (4k buffer on stack).
//! * [`decode_from_read_unbuffered_with`]: As above with custom sized stack-allocated buffer.
//! * [`decode_from_slice`]: Decode from a byte slice (errors if slice is not completely consumed).
//! * [`decode_from_slice_unbounded`]: Slice can contain additional data after decoding completes.
//! * [`decode_from_hex`]: Decode from a hex string without heap allocations.
//!
//! The following variants instead accept an agnostic [`Decoder`] type directly, instantiated with
//! [`Default`], and can be used when the output type does not implement [`Decode`]:
//!
//! * [`decode_from_read_with_decoder`]: Counterpart to [`decode_from_read`].
//! * [`decode_from_slice_with_decoder`]: Counterpart to [`decode_from_slice`].
//! * [`decode_from_slice_unbounded_with_decoder`]: Counterpart to [`decode_from_slice_unbounded`].
//! * [`decode_from_hex_with_decoder`]: Counterpart to [`decode_from_hex`].
//!
//! And on the encoding side we provide similar functions for consensus encodable types.
//!
//! * [`encode_to_writer`]: Encode to a stdlib writer.
//! * [`encode_to_vec`]: Encode to the heap.
//! * [`encode_to_hex`]: Encode to a hex string.
//!
//! As well as variants for agnostic [`Encoder`] types.
//!
//! * [`drain_to_writer`]: Drain an encoder to a stdlib writer.
//! * [`drain_to_vec`]: Drain an encoder to the heap.
//! * [`drain_to_hex`]: Drain an encoder to a hex string.
//!
//! # Collections
//!
//! This crate provides types for encoding and decoding sequences of items. On the decoding side,
//! [`VecDecoder`] decodes a length-prefixed sequence of consensus encodable types into a `Vec`.
//! [`VecDecoderWith`] and [`ExactVecDecoderWith`] are the underlying implementations, bound
//! directly on [`Decoder`] allowing them to be used with decoder types that do not have a
//! corresponding [`Decode`] implementation.
//!
//! On the encoding side, [`SliceEncoder`] and [`PrefixedSliceEncoder`] encode slices of consensus
//! encodable types without and with a compact-size length prefix respectively.
//!
//! The lower-level [`IterEncoder`] drives any iterator whose items implement [`Encoder`].
//!
//! # Feature Flags
//!
//! * `std` - Enables std lib I/O driver functions and `std::error::Error` impls (implies `alloc`).
//! * `alloc` - Enables [`encode_to_vec`], `Vec`-based decoders, and allocation-based helpers.
//! * `hex` - Enables [`decode_from_hex`], [`decode_from_hex_with_decoder`], [`encode_to_hex`] and
//!   [`drain_to_hex`]. Encoding also requires `alloc`.

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "hex")]
pub extern crate hex;
#[cfg(feature = "serde")]
pub extern crate serde;

mod compact_size;
mod decode;
mod encode;

pub mod error;
#[cfg(feature = "serde")]
pub mod serde_as_consensus;

#[doc(inline)]
pub use self::compact_size::{CompactSizeDecoder, CompactSizeEncoder, CompactSizeU64Decoder};
#[doc(inline)]
pub use self::decode::decoders::{ArrayDecoder, Decoder2, Decoder3, Decoder4, Decoder6};
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::decode::decoders::{ByteVecDecoder, ExactVecDecoderWith, VecDecoder, VecDecoderWith};
#[doc(inline)]
pub use self::decode::{
    check_decode, check_decoder, decode_from_slice, decode_from_slice_unbounded,
    decode_from_slice_unbounded_with_decoder, decode_from_slice_with_decoder, Decode, Decoder,
    DecoderStatus,
};
#[cfg(feature = "hex")]
#[doc(inline)]
pub use self::decode::{decode_from_hex, decode_from_hex_with_decoder};
#[cfg(feature = "std")]
#[doc(inline)]
pub use self::decode::{
    decode_from_read, decode_from_read_unbuffered, decode_from_read_unbuffered_with,
    decode_from_read_with_decoder,
};
#[doc(inline)]
pub use self::encode::encoders::{
    ArrayEncoder, ArrayRefEncoder, BytesEncoder, Encoder2, Encoder3, Encoder4, Encoder6,
    PrefixedBytesEncoder, PrefixedSliceEncoder, SliceEncoder,
};
#[doc(inline)]
pub use self::encode::iter::IterEncoder;
#[doc(inline)]
pub use self::encode::{
    check_encode, check_encoder, Encode, Encoder, EncoderByteIter, EncoderStatus, ExactSizeEncoder,
};
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
#[doc(inline)]
pub use self::encode::{drain_to_hex, encode_to_hex};
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::encode::{drain_to_vec, encode_to_vec};
#[cfg(feature = "std")]
#[doc(inline)]
pub use self::encode::{drain_to_writer, encode_to_writer};
#[cfg(feature = "hex")]
#[doc(no_inline)]
pub use self::error::FromHexError;
#[cfg(feature = "alloc")]
#[doc(no_inline)]
pub use self::error::LengthPrefixExceedsMaxError;
#[cfg(feature = "std")]
#[doc(no_inline)]
pub use self::error::ReadError;
#[cfg(feature = "alloc")]
#[doc(no_inline)]
pub use self::error::{ByteVecDecoderError, VecDecoderError};
#[doc(no_inline)]
pub use self::error::{
    CompactSizeDecoderError, DecodeError, Decoder2Error, Decoder3Error, Decoder4Error,
    Decoder6Error, UnconsumedError, UnexpectedEofError,
};
