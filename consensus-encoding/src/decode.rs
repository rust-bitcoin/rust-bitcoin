use super::{Decoder, ReadError};

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

super::gat_like! {
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
