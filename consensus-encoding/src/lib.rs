// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin consensus encoding/decoding.
//!
//! **Important: this crate is WIP and this is a preview version. Do **not** depend on it yet, many
//! changes are expected.
//!
//! This library provides the tools needed to implement consensus decoding and encoding.
//!

#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub use vec::*;

#[cfg(feature = "hashes")]
pub use hashes;

#[cfg(feature = "units")]
use units::Amount;

#[cfg(feature = "primitives")]
use actual_primitives::{Sequence, absolute::LockTime};

pub use push_decode::{self, Encoder, Decoder, ReadError, BufWrite};
use push_decode::int::LittleEndian;
use push_decode::decoders::combinators::Then;
use core::fmt;

/// Defines the decoder used for decoding the consensus type implementing this trait.
pub trait Decode: Sized {
    /// The decoder used when decoding this type.
    type Decoder: Decoder<Value=Self> + Default;

    /// Consensus-decodes from std reader.
    #[cfg(feature = "std")]
    fn consensus_decode<R: std::io::BufRead + ?Sized>(reader: &mut R) -> Result<Self, ReadError<<Self::Decoder as Decoder>::Error>> {
        push_decode::decode_sync_with::<Self::Decoder, _>(reader, Default::default())
    }

    /// Consensus-decodes bytes from the given slice.
    ///
    /// Note: all data must be available in the slice. To decode partially use `Decoder` instead.
    fn consensus_decode_slice(bytes: &[u8]) -> Result<Self, <Self::Decoder as Decoder>::Error> {
        let mut decoder = <Self::Decoder as Default>::default();
        decoder.bytes_received(bytes)?;
        decoder.end()
    }
}

pub trait EncodeTc<'a> {
    type Encoder: Encoder;
}

pub trait Encode: for<'a> EncodeTc<'a> {
    /// Minimum number of bytes needed to encode this value.
    const MIN_ENCODED_LEN: usize;
    /// True if the encoded length is known, false if not.
    const IS_KNOWN_LEN: bool;

    /// Creates an encoder producing conensus-encoded `Self`.
    fn encoder(&self) -> <Self as EncodeTc<'_>>::Encoder;

    fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize);

    fn reserve_suggestion(&self, max_steps: usize) -> (usize, usize) {
        if Self::IS_KNOWN_LEN {
            debug_assert_eq!(self.dyn_encoded_len(usize::MAX).0, 0);
            (Self::MIN_ENCODED_LEN, max_steps)
        } else {
            let (len, max_steps) = self.dyn_encoded_len(max_steps);
            (Self::MIN_ENCODED_LEN + len, max_steps)
        }
    }

    fn count_consensus_bytes(&self) -> usize {
        if Self::IS_KNOWN_LEN {
            Self::MIN_ENCODED_LEN
        } else {
            let mut encoder = self.encoder();
            let mut total = 0;
            while !encoder.encoded_chunk().is_empty() {
                total += encoder.encoded_chunk().len();
                if !encoder.next() {
                    break;
                }
            }
            total
        }
    }

    /// Consensus-encodes the value and stores the bytes in a vec.
    #[cfg(feature = "alloc")]
    fn consensus_encode_to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::with_capacity(self.reserve_suggestion(20).0);
        self.encoder().write_to_vec(&mut buf);
        buf
    }

    /// Consensus-encodes the value and writes it into a buffered `std` writer.
    ///
    /// # Errors
    ///
    /// This only returns errors originating from the passed-in `writer`.
    #[cfg(feature = "std")]
    fn consensus_encode<W: std::io::Write + BufWrite>(&self, writer: &mut W) -> std::io::Result<()> {
        self.encoder().write_all_sync(writer)
    }

    /// Feeds the consensus-encoded data into the hash engine.
    #[cfg(feature = "hashes")]
    fn consensus_encode_to_hash_engine<E: hashes::HashEngine>(&self, engine: &mut E) {
        self.encoder().hash_to_engine(engine)
    }

    /// Returns the hash of consensus data.
    #[cfg(feature = "hashes")]
    fn hash_consensus_encoded<H: hashes::GeneralHash>(&self) -> H {
        self.encoder().hash()
    }
}

pub trait EncoderExt: Encoder {
    #[cfg(feature = "hashes")]
    fn hash<H: hashes::GeneralHash>(self) -> H {
        let mut engine = H::engine();
        self.hash_to_engine(&mut engine);
        H::from_engine(engine)
    }

    #[cfg(feature = "hashes")]
    fn hash_to_engine<E: hashes::HashEngine>(mut self, engine: &mut E) {
        while !self.encoded_chunk().is_empty() {
            engine.input(self.encoded_chunk());
            if !self.next() {
                break;
            }
        }
    }
}

impl<T: Encoder> EncoderExt for T {}

#[macro_export]
macro_rules! gat_like {
    (impl$(<$($bounded_gen:tt)*>)? Encode for $value:ty { type Encoder<$lifetime:lifetime> = $encoder:ty $(where Self: $bound_lifetime:lifetime)?; const MIN_ENCODED_LEN: usize = $min_len:expr; const IS_KNOWN_LEN: bool = $is_known_len:expr; $(#[$($constructor_attr:tt)*])* fn encoder(&$self:ident) -> Self::Encoder<'_> { $($encoder_constructor:tt)* } $($remaining:tt)* }) => {
        $(
            // Idea copied from the static-cond crate.
            macro_rules! __bitcoin_consensus_encoding_check_lifetimes {
                ($lifetime, $lifetime) => {};
                ($lifetime, $bound_lifetime) => { compile_error!("The lifetime in the `where Self: '` bound doesn't match the one in \"GAT\""); };
            }

            __bitcoin_consensus_encoding_check_lifetimes!($lifetime, $bound_lifetime);
        )?

        impl<$lifetime $(, $($bounded_gen)*)?> $crate::EncodeTc<$lifetime> for $value {
            type Encoder = $encoder;
        }

        impl$(<$($bounded_gen)*>)? $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = $min_len;
            const IS_KNOWN_LEN: bool = $is_known_len;

            $(#[$($constructor_attr)*])*
            fn encoder(&$self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $($encoder_constructor)*
            }

            $($remaining)*
        }
    }
}

// TODO: should we have this (and more importantly other integers) or just use the decoder directly?
impl Decode for u8 {
    type Decoder = push_decode::decoders::U8Decoder;
}

gat_like! {
    impl Encode for u8 {
        type Encoder<'a> = push_decode::encoders::BytesEncoder<[u8; 1]>;

        const MIN_ENCODED_LEN: usize = 1;
        const IS_KNOWN_LEN: bool = true;

        #[inline]
        fn encoder(&self) -> Self::Encoder<'_> {
            push_decode::encoders::BytesEncoder::new([*self])
        }

        #[inline]
        fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
            (0, max_steps)
        }
    }
}

pub use push_decode::encoders::IntEncoder;

macro_rules! ints {
    ($($int:ty),*) => {
        $(
            impl Decode for $int {
                type Decoder = push_decode::decoders::IntDecoder<Self, LittleEndian>;
            }

            gat_like! {
                impl Encode for $int {
                    type Encoder<'a> = IntEncoder<$int>;

                    const MIN_ENCODED_LEN: usize = core::mem::size_of::<$int>();
                    const IS_KNOWN_LEN: bool = true;

                    #[inline]
                    fn encoder(&self) -> Self::Encoder<'_> {
                        IntEncoder::new_le(*self)
                    }

                    #[inline]
                    fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                        (0, max_steps)
                    }
                }
            }
        )*
    }
}

ints!(u16, u32, u64, u128, i16, i32, i64, i128);

/// Implements `Decode` and a `Decoder` for given structured type
///
/// This is for types where each field is directly encoded, in order.
#[macro_export]
macro_rules! impl_struct_decode {
    (($value:ident, $error:ident) => $decoder_vis:vis struct $decoder:ident { $($(#[$($variant_attr:tt)*])* $variant:ident { $field:ident: $ty:ty }),* $(,)? }) => {
        impl $crate::Decode for $value {
            type Decoder = $decoder;
        }

        #[doc = "`"]
        #[doc = stringify!($value)]
        #[doc = "` decoder."]
        #[derive(Default, Debug)]
        $decoder_vis struct $decoder {
            decoder_state: u8,
            $($field: <$ty as $crate::Decode>::Decoder,)*
        }

        impl $crate::Decoder for $decoder {
            type Value = $value;
            type Error = $error;

            fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
                let mut counter = 0;
                $(let $field = counter; counter += 1;)*
                let _ = counter;
                $(if self.decoder_state == $field {
                    self.$field.decode_chunk(bytes).map_err($error::$variant)?;
                    if !bytes.is_empty() {
                        self.decoder_state += 1;
                    } else {
                        return Ok(());
                    }
                })*
                return Ok(());
            }

            fn end(self) -> Result<Self::Value, Self::Error> {
                $(let $field = self.$field.end().map_err($error::$variant)?; )*
                Ok($value {
                    $($field,)*
                })
            }
        }

        #[doc = "Error returned when consensus-decoding `"]
        #[doc = stringify!($value)]
        #[doc = "` fails."]
        #[derive(Debug)]
        $decoder_vis enum $error {
            $($(#[$($variant_attr)*])* $variant(<<$ty as $crate::Decode>::Decoder as $crate::Decoder>::Error),)*
        }

        #[cfg(feature = "std")]
        impl std::error::Error for $error
            where Self: std::fmt::Display $(, <<$ty as $crate::Decode>::Decoder as $crate::Decoder>::Error: std::error::Error + 'static)*
        {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        Self::$variant(error) => Some(error),
                    )*
                }
            }
        }
    }
}

// Note: this horrible macro is required because Rust doesn't allow generating match arms directly.
// Stolen from https://users.rust-lang.org/t/how-to-generate-in-macro/56774/4
#[doc(hidden)]
#[macro_export]
macro_rules! impl_struct_encode_next {
    ($self:expr, $state:ident $(, ($field:ident, $variant:ident))*) => {
        $crate::impl_struct_encode_next!(@($self, $state $(, ($field, $variant))*))
    };
    (@($self:expr, $state:ident, ($field:ident, $variant:ident)) $($arms:tt)*) => {
        match &mut $self.state {
            $($arms)*
            $state::$variant (encoder) => encoder.next()
        }
    };
    (@($self:expr, $state:ident, ($field:ident, $variant:ident), ($next_field:ident, $next_variant:ident) $(, ($remaining_fields:ident, $remaining_variants:ident))*) $($arms:tt)*) => {
        $crate::impl_struct_encode_next! {
            @($self, $state, ($field, $next_variant) $(, ($remaining_fields, $remaining_variants))*)
                $($arms)*

                $state::$variant (encoder) => {
                    if encoder.next() {
                        true
                    } else {
                        let encoder = $crate::Encode::encoder(&$self.value.$next_field);
                        $self.state = $state::$next_variant(encoder);
                        true
                    }
                }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_struct_encode_encoder_constructor {
    ($encoder:ident, $encoder_state:ident, $variant:ident, $field:ident $(, $($whatever:tt)*)?) => {
        fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
            $encoder {
                value: self,
                state: $encoder_state::$variant(self.$field.encoder()),
            }
        }
    }
}

/// Implements [`EncodeTc`], [`Encode`] and a [`Encoder`] for given structured type.
///
/// This is for types where each field is directly encoded, in order.
///
/// WARNING: currently doens't work if any of the fields produces empty serialization.
#[macro_export]
macro_rules! impl_struct_encode {
    ($value:ty => $encoder_vis:vis struct $encoder:ident { $($(#[$($variant_attr:tt)*])* $variant:ident { $field:ident: $ty:ty }),+ $(,)? } enum $encoder_state:ident<'_> { ... }) => {

        #[doc = "Encoder of [`"]
        #[doc = stringify!($value)]
        #[doc = "`]\n"]
        #[doc = "\n"]
        #[doc = "For more information about encoders check the `Encoder` trait"]
        $encoder_vis struct $encoder<'a> {
            value: &'a $value,
            state: $encoder_state<'a>,
        }

        enum $encoder_state<'a> {
            $($variant(<$ty as $crate::EncodeTc<'a>>::Encoder),)*
        }

        impl<'a> $crate::EncodeTc<'a> for $value {
            type Encoder = $encoder<'a>;
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = 0 $(+ <$ty as $crate::Encode>::MIN_ENCODED_LEN)*;
            const IS_KNOWN_LEN: bool = true $(&& <$ty as $crate::Encode>::IS_KNOWN_LEN)*;

            $crate::impl_struct_encode_encoder_constructor!($encoder, $encoder_state, $($variant, $field),*);

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                if Self::IS_KNOWN_LEN {
                    (0, max_steps)
                } else {
                    if max_steps == 0 {
                        return (0, 0);
                    }

                    let mut total = 0;
                    $(
                        // This avoids reliance on inlining to optimize-out calls to
                        // dyn_encoded_len for known-len types.
                        let max_steps = if <$ty as $crate::Encode>::IS_KNOWN_LEN {
                            max_steps
                        } else {
                            let (len, max_steps) = $crate::Encode::dyn_encoded_len(&self.$field, max_steps - 1);
                            total += len;
                            if max_steps == 0 {
                                return (total, 0);
                            }
                            max_steps
                        };
                    )+
                    (total, max_steps)
                }
            }
        }

        impl $crate::Encoder for $encoder<'_> {
            fn encoded_chunk(&self) -> &[u8] {
                match &self.state {
                    $(
                        $encoder_state::$variant(state) => $crate::Encoder::encoded_chunk(state),
                    )*
                }
            }

            fn next(&mut self) -> bool {
                $crate::impl_struct_encode_next!(self, $encoder_state $(, ($field, $variant))*)
            }
        }
    }
}

/// Creates a newtype for an encoder.
///
/// Has three levels:
///
/// * Just the encoders struct (without specifying `$value`)
/// * The encoder struct and `EncodeTc` (without `map ...`)
/// * Full implementation - uses conversion to an intermediate type
#[macro_export]
macro_rules! encoder_newtype {
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty);) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`]\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $vis struct $encoder<$lifetime>($inner);
        }

        impl<$lifetime> $crate::EncodeTc<$lifetime> for $value {
            type Encoder = $encoder<$lifetime>;
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident($inner:ty);) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`]\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $vis struct $encoder($inner);
        }

        impl<'a> $crate::EncodeTc<'a> for $value {
            type Encoder = $encoder;
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty) map $intermediate:ty as $fun:expr;) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`].\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $value => $vis struct $encoder<$lifetime>($inner);
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = <$intermediate as $crate::Encode>::MIN_ENCODED_LEN;
            const IS_KNOWN_LEN: bool = <$intermediate as $crate::Encode>::IS_KNOWN_LEN;

            fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $encoder($crate::Encode::encoder(&($fun)(self)))
            }

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                $crate::Encode::dyn_encoded_len((&$fun)(self), max_steps)
            }
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident($inner:ty) map $intermediate:ty as $fun:expr;) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`].\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $value => $vis struct $encoder($inner);
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = <$intermediate as $crate::Encode>::MIN_ENCODED_LEN;
            const IS_KNOWN_LEN: bool = <$intermediate as $crate::Encode>::IS_KNOWN_LEN;

            fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $encoder($crate::Encode::encoder(&($fun)(self)))
            }

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                $crate::Encode::dyn_encoded_len(&($fun)(self), max_steps)
            }
        }
    };
    ($(#[$($attr:tt)*])* $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty);) => {
        $(#[$($attr)*])*
        $vis struct $encoder<$lifetime>($inner);

        impl<$lifetime> $crate::Encoder for $encoder<$lifetime> {
            fn encoded_chunk(&self) -> &[u8] {
                $crate::Encoder::encoded_chunk(&self.0)
            }

            fn next(&mut self) -> bool {
                $crate::Encoder::next(&mut self.0)
            }
        }
    };
    ($(#[$($attr:tt)*])* $vis:vis struct $encoder:ident($inner:ty);) => {
        $(#[$($attr)*])*
        $vis struct $encoder($inner);

        impl $crate::Encoder for $encoder {
            fn encoded_chunk(&self) -> &[u8] {
                $crate::Encoder::encoded_chunk(&self.0)
            }

            fn next(&mut self) -> bool {
                $crate::Encoder::next(&mut self.0)
            }
        }
    };
}

/// Implements `Decode` and a `Decoder` for given hash type.
///
/// This directly reads the appropriate amount of bytes without transformation.
#[cfg(feature = "hashes")]
#[macro_export]
macro_rules! hash_decoder {
    ($($hash_type:ty => $vis:vis $decoder:ident;)*) => {
        $crate::push_decode::mapped_decoder! {
            $(
                #[doc = "`"]
                #[doc = stringify!($hash_type)]
                #[doc = "` decoder."]
                #[doc = "\n"]
                #[doc = "For more information about decoder see the documentation of the [`Decoder`]("]
                #[doc = stringify!($crate)]
                #[doc = "::Decoder) trait."]
                #[derive(Debug, Default)]
                $vis struct $decoder($crate::push_decode::decoders::ByteArrayDecoder<{<$hash_type as $crate::hashes::Hash>::LEN}>) using $hash_type => <$hash_type as $crate::hashes::Hash>::from_byte_array;
            )*
        }

        $(
            impl $crate::Decode for $hash_type {
                type Decoder = $decoder;
            }
        )*
    }
}

/// Implements `Encode` and a `Encoder` for given hash type.
///
/// This directly reads the appropriate amount of bytes without transformation.
#[cfg(feature = "hashes")]
#[macro_export]
macro_rules! hash_encoder {
    ($($hash_type:ty;)*) => {
        $(
            impl<'a> $crate::EncodeTc<'a> for $hash_type {
                // We intentionally use array rather than slice to get a thin pointer.
                type Encoder = $crate::push_decode::encoders::BytesEncoder<&'a <$hash_type as $crate::hashes::Hash>::Bytes>;
            }

            impl $crate::Encode for $hash_type {
                const MIN_ENCODED_LEN: usize = <Self as $crate::hashes::Hash>::LEN;
                const IS_KNOWN_LEN: bool = true;

                fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                    $crate::push_decode::encoders::BytesEncoder::new(self.as_byte_array())
                }

                fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                    (0, max_steps)
                }
            }
        )*
    }
}

/// Implements `Decode` for a type by wrapping its decoder in a newtype and calling a function to
/// transform it.
#[macro_export]
macro_rules! mapped_decoder {
    ($($value:ty => $(#[$($attr:tt)*])* $vis:vis struct $name:ident($inner:ty) using $func:expr;)*) => {
        $(
            $crate::push_decode::mapped_decoder! {
                #[doc = "`"]
                #[doc = stringify!($value)]
                #[doc = "` decoder."]
                $(#[$($attr)*])*
                #[derive(Debug)]
                $vis struct $name($inner) using $value => $func;
            }

            impl $crate::Decode for $value {
                type Decoder = $name;
            }
        )*
    }
}

#[cfg(feature = "units")]
mapped_decoder! {
    Amount => #[derive(Default)] pub struct AmountDecoder(<u64 as Decode>::Decoder) using Amount::from_sat;
}

#[cfg(feature = "units")]
encoder_newtype! {
    Amount => pub struct AmountEncoder(<u64 as EncodeTc<'static>>::Encoder);
}

#[cfg(feature = "units")]
impl Encode for Amount {
    const MIN_ENCODED_LEN: usize = 8;
    const IS_KNOWN_LEN: bool = true;

    fn encoder(&self) -> <Self as EncodeTc<'_>>::Encoder {
        AmountEncoder(self.to_sat().encoder())
    }

    fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
        (0, max_steps)
    }
}

#[cfg(feature = "primitives")]
mapped_decoder! {
    Sequence => #[derive(Default)] pub struct SequenceDecoder(<u32 as Decode>::Decoder) using Sequence;
}

#[cfg(feature = "primitives")]
encoder_newtype! {
    Sequence => pub struct SequenceEncoder(IntEncoder<u32>)
        map u32 as |sequence: &Sequence| sequence.to_consensus_u32();
}

#[cfg(feature = "primitives")]
mapped_decoder! {
    LockTime => #[derive(Default)] pub struct LockTimeDecoder(<u32 as Decode>::Decoder) using LockTime::from_consensus;
}

#[cfg(feature = "primitives")]
encoder_newtype! {
    LockTime => pub struct LockTimeEncoder(push_decode::encoders::IntEncoder<u32>) map u32 as |lock_time: &LockTime| lock_time.to_consensus_u32();
}

/// Decodes a varint.
///
/// For more information about decoder see the documentation of the [`Decoder`] trait.
#[derive(Default, Debug, Clone)]
pub struct VarIntDecoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
}

impl Decoder for VarIntDecoder {
    type Value = u64;
    type Error = VarIntDecodeError;

    fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        if bytes.is_empty() { return Ok(()); }
        if self.buf.is_empty() {
            self.buf.push(bytes[0]);
            *bytes = &bytes[1..];
        }
        let max_len = match self.buf[0] {
            0xFF => 9,
            0xFE => 5,
            0xFD => 3,
            _ => 1
        };
        let to_copy = bytes.len().min(max_len - self.buf.len());
        self.buf.extend_from_slice(&bytes[..to_copy]);
        *bytes = &bytes[to_copy..];
        Ok(())
    }

    fn end(self) -> Result<Self::Value, Self::Error> {
        fn arr<const N: usize>(slice: &[u8]) -> Result<[u8; N], VarIntDecodeError> {
            slice.try_into().map_err(|_| {
                VarIntDecodeError::UnexpectedEnd { required: N, received: slice.len() }
            })
        }

        let (first, payload) = self.buf.split_first()
            .ok_or(VarIntDecodeError::UnexpectedEnd { required: 1, received: 0 })?;
        match *first {
            0xFF => {
                let x =  u64::from_le_bytes(arr(payload)?);
                if x < 0x100000000 {
                    Err(VarIntDecodeError::NonMinimal { value: x })
                } else {
                    Ok(x)
                }
            },
            0xFE => {
                let x =  u32::from_le_bytes(arr(payload)?);
                if x < 0x10000 {
                    Err(VarIntDecodeError::NonMinimal { value: x.into() })
                } else {
                    Ok(x.into())
                }
            },
            0xFD => {
                let x =  u16::from_le_bytes(arr(payload)?);
                if x < 0xFD {
                    Err(VarIntDecodeError::NonMinimal { value: x.into() })
                } else {
                    Ok(x.into())
                }
            },
            n => {
                Ok(n.into())
            },
        }
    }
}

/// Encodes a varint.
pub struct VarIntEncoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
}

impl VarIntEncoder {
    pub fn new(value: u64) -> Self {
        // In theory, varint consists of two parts: prefix and optional payload, so this could have
        // two states, one for each part. However we need to have some buffer anyway because of
        // trait requirement to return `&[u8]`, so we use ArrayVec and while we're at it it makes a
        // lot of sense to just encode everything upfront.
        let mut buf = internals::array_vec::ArrayVec::new();
        match value {
            0..=0xFC => {
                buf.push(value as u8);
            }
            0xFD..=0xFFFF => {
                buf.push(0xFD);
                buf.extend_from_slice(&(value as u16).to_le_bytes());
            }
            0x10000..=0xFFFFFFFF => {
                buf.push(0xFE);
                buf.extend_from_slice(&(value as u32).to_le_bytes());
            }
            _ => {
                buf.push(0xFF);
                buf.extend_from_slice(&value.to_le_bytes());
            }
        }

        VarIntEncoder { buf }
    }

    pub fn len(value: u64) -> usize {
        Self::payload_len(value) + 1
    }

    fn payload_len(value: u64) -> usize {
        match value {
            0..=0xFC => {
                0
            }
            0xFD..=0xFFFF => {
                2
            }
            0x10000..=0xFFFFFFFF => {
                4
            }
            _ => {
                8
            }
        }
    }

    pub fn dyn_encoded_len(value: u64, max_steps: usize) -> (usize, usize) {
        if max_steps == 0 {
            return (0, 0)
        }
        (Self::payload_len(value), max_steps - 1)
    }

}

impl Encoder for VarIntEncoder {
    fn encoded_chunk(&self) -> &[u8] {
        &self.buf
    }

    fn next(&mut self) -> bool {
        false
    }
}

/// Returned when decoding a var int fails.
#[derive(Debug)]
pub enum VarIntDecodeError {
    UnexpectedEnd { required: usize, received: usize },
    NonMinimal { value: u64 },
}

impl fmt::Display for VarIntDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { required: 1, received: 0 } => write!(f, "required at least one byte but the input is empty"),
            Self::UnexpectedEnd { required, received: 0 } => write!(f, "required at least {} bytes but the input is empty", required),
            Self::UnexpectedEnd { required, received } => write!(f, "required at least {} bytes but only {} bytes were received", required, received),
            Self::NonMinimal { value } => write!(f, "the value {} was not encoded minimally", value),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VarIntDecodeError {}

pub type SliceEncoder<'a, T> = IterEncoder<'a, T, core::slice::Iter<'a, T>>;

pub struct IterEncoder<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator>(push_decode::encoders::combinators::Chain<VarIntEncoder, UnprefixedIterEncoder<'a, T, I>>);

impl<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator> IterEncoder<'a, T, I> {
    pub fn new<U: IntoIterator<IntoIter=I>>(iter: U) -> Self {
        let iter = iter.into_iter();
        let first_encoder = VarIntEncoder::new(iter.len() as u64);
        let second_encoder = UnprefixedIterEncoder::new(iter);

        IterEncoder(first_encoder.chain(second_encoder))
    }

    pub fn dyn_len(iter: impl IntoIterator<IntoIter=I>, max_steps: usize) -> (usize, usize) {
        let iter = iter.into_iter();
        let (varint_len, max_steps) = VarIntEncoder::dyn_encoded_len(iter.len() as u64, max_steps);
        if max_steps == 0 {
            return (varint_len, 0);
        }
        let (data_len, max_steps) = UnprefixedIterEncoder::dyn_len(iter, max_steps - 1);
        (data_len + varint_len, max_steps)
    }
}

pub struct UnprefixedIterEncoder<'a, T: Encode, I: Iterator<Item=&'a T>>(InnerIterEncoder<'a, T, I>);

impl<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator> UnprefixedIterEncoder<'a, T, I> {
    pub fn new<U: IntoIterator<IntoIter=I>>(iter: U) -> Self {
        let mut iter = iter.into_iter().fuse();
        // Empty elements must be skipped
        let state = loop {
            match iter.next() {
                Some(first) => {
                    let encoder = first.encoder();
                    if !encoder.encoded_chunk().is_empty() {
                        break InnerIterEncoder::Encoding { current: encoder, remaining: iter };
                    }
                },
                None => break InnerIterEncoder::Done,
            }
        };
        Self(state)
    }

    pub fn dyn_len(iter: impl IntoIterator<IntoIter=I>, mut max_steps: usize) -> (usize, usize) {
        let iter = iter.into_iter();
        if max_steps == 0 {
            return (0, 0);
        }
        let mut total = T::MIN_ENCODED_LEN * iter.len();
        max_steps -= 1;
        if !T::IS_KNOWN_LEN {
            for element in iter {
                let (len, new_max_steps) = element.dyn_encoded_len(max_steps);
                total += len;
                if new_max_steps == 0 {
                    return (total, 0);
                }
                max_steps = new_max_steps;
            }
        }
        (total, max_steps)
    }
}

impl<'a, T: Encode, I: Iterator<Item=&'a T> + ExactSizeIterator> Encoder for IterEncoder<'a, T, I> {
    fn encoded_chunk(&self) -> &[u8] {
        self.0.encoded_chunk()
    }

    fn next(&mut self) -> bool {
        self.0.next()
    }
}

enum InnerIterEncoder<'a, T: Encode + 'a, I: Iterator<Item=&'a T>> {
    Encoding { current: <T as EncodeTc<'a>>::Encoder, remaining: core::iter::Fuse<I> },
    Done,
}

impl<'a, T: Encode, I: Iterator<Item=&'a T>> Encoder for UnprefixedIterEncoder<'a, T, I> {
    fn encoded_chunk(&self) -> &[u8] {
        match &self.0 {
            InnerIterEncoder::Encoding { current, .. } => current.encoded_chunk(),
            InnerIterEncoder::Done => &[],
        }
    }

    fn next(&mut self) -> bool {
        match &mut self.0 {
            InnerIterEncoder::Encoding { current, remaining } => {
                if current.next() {
                    true
                } else {
                    loop {
                        match remaining.next() {
                            Some(next) => {
                                *current = next.encoder();
                                if !current.encoded_chunk().is_empty() {
                                    break true;
                                }
                            },
                            None => {
                                self.0 = InnerIterEncoder::Done;
                                break false;
                            }
                        }
                    }
                }
            },
            InnerIterEncoder::Done => false,
        }
    }
}

#[cfg(feature = "alloc")]
mod vec {
    use super::*;
    use alloc::vec::Vec;

    #[allow(clippy::type_complexity)] // doesn't seem really that complex
    pub struct VecDecoder<T: Decode>(Then<VarIntDecoder, InnerVecDecoder<T>, fn (u64) -> InnerVecDecoder<T>>) where T::Decoder: Default;

    impl<T: Decode> Decoder for VecDecoder<T> where T::Decoder: Default {
        type Value = Vec<T>;
        type Error = VecDecodeError<<T::Decoder as Decoder>::Error>;

        fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
            self.0.decode_chunk(bytes).map_err(|error| {
                error
                    .map_left(VecDecodeError::Length)
                    .map_right(|(error, position)| VecDecodeError::Element { error, position })
                    .either_into()
            })
        }

        fn end(self) -> Result<Self::Value, Self::Error> {
            // TODO: unexpected end
            self.0.end().map_err(|error| {
                error
                    .map_left(VecDecodeError::Length)
                    .map_right(|(error, position)| VecDecodeError::Element { error, position })
                    .either_into()
            })
        }
    }

    impl<T> fmt::Debug for VecDecoder<T> where T: Decode + fmt::Debug, T::Decoder: Default + fmt::Debug {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_tuple("VecDecoder")
                .field(&self.0)
                .finish()
        }
    }

    /// Returned when decoding a varint-prefixed `Vec` of decodable element fails to parse.
    #[derive(Debug)]
    pub enum VecDecodeError<E> {
        /// Failed decoding length (varint).
        Length(VarIntDecodeError),
        /// Failed to decode element .
        Element { error: E, position: usize },
        UnexpectedEnd,
    }

    impl<E: fmt::Display> fmt::Display for VecDecodeError<E> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use internals::write_err;

            match self {
                Self::Length(error) => write_err!(f, "failed to parse length"; error),
                Self::Element { error, position } => write_err!(f, "failed to parse element at position {} (starting from 0)", position; error),
                Self::UnexpectedEnd => write!(f, "the input reached end (EOF) unexpectedly"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<E: std::error::Error + 'static> std::error::Error for VecDecodeError<E> {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Length(error) => Some(error),
                Self::Element { error, .. } => Some(error),
                Self::UnexpectedEnd => None,
            }
        }
    }

    impl<T: Decode> Default for VecDecoder<T> where T::Decoder: Default {
        fn default() -> Self {
            VecDecoder(VarIntDecoder::default().then(|len| {
                let cap = len.min(4000000) as usize;
                InnerVecDecoder {
                    vec: Vec::with_capacity(cap),
                    required: len as usize,
                    decoder: Default::default(),
                }
            }))
        }
    }


    struct InnerVecDecoder<T: Decode> where T::Decoder: Default {
        vec: Vec<T>,
        required: usize,
        decoder: T::Decoder,
    }

    impl<T> fmt::Debug for InnerVecDecoder<T> where T: Decode + fmt::Debug, T::Decoder: Default + fmt::Debug {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("InnerVecDecoder")
                .field("vec", &self.vec)
                .field("required", &self.required)
                .field("decoder", &self.decoder)
                .finish()
        }
    }

    impl<T: Decode> Decoder for InnerVecDecoder<T> where T::Decoder: Default {
        type Value = Vec<T>;
        type Error = (<T::Decoder as Decoder>::Error, usize);

        fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
            while self.vec.len() < self.required {
                self.decoder.decode_chunk(bytes).map_err(|error| (error, self.vec.len()))?;
                if !bytes.is_empty() {
                    let item = self.decoder.take().map_err(|error| (error, self.vec.len()))?;
                    self.vec.push(item);
                } else {
                    return Ok(())
                }
            }
            Ok(())
        }

        fn end(mut self) -> Result<Self::Value, Self::Error> {
            while self.vec.len() < self.required {
                // If the item is zero-sized this will just produce enough
                // If the item is not zero sized this will error which is what we want
                let item = self.decoder.take().map_err(|error| (error, self.vec.len()))?;
                self.vec.push(item);
            }
            Ok(self.vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Decode, Encode};
    use core::fmt;

    #[test]
    fn impl_struct_de() {
        struct Foo {
            bar: u32,
            baz: u64,
        }

        impl_struct_decode! {
            (Foo, FooDecodeError) => struct Decoder {
                Bar { bar: u32 },
                Baz { baz: u64 },
            }
        }

        impl fmt::Display for FooDecodeError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    FooDecodeError::Bar(error) => fmt::Display::fmt(error, f),
                    FooDecodeError::Baz(error) => fmt::Display::fmt(error, f),
                }
            }
        }

        let foo = Foo::consensus_decode_slice(&[0x2a, 0x00, 0x00, 0x00, 0x00, 0x40, 0x07, 0x5a, 0xf0, 0x75, 0x07, 0x00]).unwrap();
        assert_eq!(foo.bar, 42);
        assert_eq!(foo.baz, 2100000000000000);
    }


    #[test]
    fn impl_struct_en() {
        struct Foo {
            bar: u32,
            baz: u64,
        }

        impl_struct_encode! {
            Foo => struct Encoder {
                Bar { bar: u32 },
                Baz { baz: u64 },
            }

            enum EncoderState<'_> { ... }
        }

        let foo = Foo {
            bar: 42,
            baz: 2100000000000000,
        };
        assert_eq!(foo.consensus_encode_to_vec(), [42, 0, 0, 0, 0, 64, 7, 90, 240, 117, 7, 0]);
    }
}
