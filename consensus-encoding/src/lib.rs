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

#[macro_use]
mod decode;
#[macro_use]
mod encode;
mod varint;
#[cfg(feature = "alloc")]
mod vec;
#[cfg(feature = "units")]
mod units_impls;
#[cfg(feature = "primitives")]
mod primitives_impls;

pub use decode::*;
pub use encode::*;
pub use varint::*;
#[cfg(feature = "units")]
pub use units_impls::*;
#[cfg(feature = "primitives")]
pub use primitives_impls::*;

#[cfg(feature = "alloc")]
pub use vec::*;

#[cfg(feature = "hashes")]
pub use hashes;

pub use push_decode::{self, Encoder, Decoder, ReadError, BufWrite};
use push_decode::int::LittleEndian;
use push_decode::decoders::combinators::Then;
use core::fmt;

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
