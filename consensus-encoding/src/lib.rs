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

pub use push_decode::{self, Encoder, Decoder, ReadError};
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

// TODO: should we have this (and more importantly other integers) or just use the decoder directly?
impl Decode for u8 {
    type Decoder = push_decode::decoders::U8Decoder;
}

macro_rules! ints {
    ($($int:ty),*) => {
        $(
            impl Decode for $int {
                type Decoder = push_decode::decoders::IntDecoder<Self, LittleEndian>;
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

#[cfg(feature = "primitives")]
mapped_decoder! {
    Sequence => #[derive(Default)] pub struct SequenceDecoder(<u32 as Decode>::Decoder) using Sequence;
}

#[cfg(feature = "primitives")]
mapped_decoder! {
    LockTime => #[derive(Default)] pub struct LockTimeDecoder(<u32 as Decode>::Decoder) using LockTime::from_consensus;
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
    use super::Decode;
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
}
