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
    }
}

/// Implements `Decode` and a `Decoder` for given hash type.
///
/// This directly reads the appropriate amount of bytes without transformation.
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
                $vis struct $decoder($crate::push_decode::decoders::ByteArrayDecoder<{<$hash_type>::LEN}>) using $hash_type => <$hash_type>::from_byte_array;
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

/// Decodes a varint.
///
/// For more information about decoder see the documentation of the [`Decoder`] trait.
#[derive(Default, Debug, Clone)]
pub struct VarIntDecoder {
    buf: [u8; 9],
    pos: usize,
}

impl Decoder for VarIntDecoder {
    type Value = u64;
    type Error = VarIntDecodeError;

    fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        if bytes.is_empty() { return Ok(()); }
        if self.pos == 0 {
            self.buf[0] = bytes[0];
            *bytes = &bytes[1..];
            self.pos += 1;
        }
        let max_len = match self.buf[0] {
            0xFF => 9,
            0xFE => 5,
            0xFD => 3,
            _ => 1
        };
        let to_copy = bytes.len().min(max_len - self.pos);
        self.buf[self.pos..(self.pos + to_copy)].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        *bytes = &bytes[to_copy..];
        Ok(())
    }

    fn end(self) -> Result<Self::Value, Self::Error> {
        fn check_len(pos: usize, required: usize) -> Result<(), VarIntDecodeError> {
            if pos < required {
                Err(VarIntDecodeError::UnexpectedEnd { required, received: pos })
            } else {
                Ok(())
            }
        }

        check_len(self.pos, 1)?;
        match self.buf[0] {
            0xFF => {
                check_len(self.pos, 9)?;
                let x =  u64::from_le_bytes(self.buf[1..9].try_into().expect("statically known"));
                if x < 0x100000000 {
                    Err(VarIntDecodeError::NonMinimal { value: x })
                } else {
                    Ok(x)
                }
            },
            0xFE => {
                check_len(self.pos, 5)?;
                let x =  u32::from_le_bytes(self.buf[1..5].try_into().expect("statically known"));
                if x < 0x10000 {
                    Err(VarIntDecodeError::NonMinimal { value: x.into() })
                } else {
                    Ok(x.into())
                }
            },
            0xFD => {
                check_len(self.pos, 3)?;
                let x =  u16::from_le_bytes(self.buf[1..3].try_into().expect("statically known"));
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

#[cfg(feature = "alloc")]
mod vec {
    use super::*;
    use alloc::vec::Vec;

    /*
    impl<T: Decode> Decode for Vec<T> where T::Decoder: Default {
        type Decoder = VecDecoder<T>;
    }
    */

    pub struct VecDecoder<T: Decode>(Then<VarIntDecoder, InnerVecDecoder<T>, fn (u64) -> InnerVecDecoder<T>>) where T::Decoder: Default;

    impl<T: Decode> Decoder for VecDecoder<T> where T::Decoder: Default {
        type Value = Vec<T>;
        type Error = VecDecodeError<<T::Decoder as Decoder>::Error>;

        fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
            self.0.decode_chunk(bytes).map_err(|error| {
                error.map_left(VecDecodeError::Length).map_right(VecDecodeError::Element).either_into()
            })
        }

        fn end(self) -> Result<Self::Value, Self::Error> {
            // TODO: unexpected end
            self.0.end().map_err(|error| {
                error.map_left(VecDecodeError::Length).map_right(VecDecodeError::Element).either_into()
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

    #[derive(Debug)]
    pub enum VecDecodeError<E> {
        Length(VarIntDecodeError),
        Element(E),
        UnexpectedEnd,
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
        type Error = <T::Decoder as Decoder>::Error;

        fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
            while self.vec.len() < self.required {
                self.decoder.decode_chunk(bytes)?;
                if !bytes.is_empty() {
                    let item = core::mem::take(&mut self.decoder).end()?;
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
                let item = core::mem::take(&mut self.decoder).end()?;
                self.vec.push(item);
            }
            Ok(self.vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Decode;

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

        let foo = Foo::consensus_decode_slice(&[0x2a, 0x00, 0x00, 0x00, 0x00, 0x40, 0x07, 0x5a, 0xf0, 0x75, 0x07, 0x00]).unwrap();
        assert_eq!(foo.bar, 42);
        assert_eq!(foo.baz, 2100000000000000);
    }
}
