// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Connection Bloom filtering network messages.
//!
//! This module describes BIP-0037 Connection Bloom filtering network messages.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, Decoder4, Encoder2, Encoder3, PrefixedBytesEncoder,
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{BloomFlagsDecoderError, FilterAddDecoderError, FilterLoadDecoderError};

/// `filterload` message sets the current bloom filter
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterLoad {
    /// The filter itself
    pub filter: Vec<u8>,
    /// The number of hash functions to use
    pub hash_funcs: u32,
    /// A random value
    pub tweak: u32,
    /// Controls how matched items are added to the filter
    pub flags: BloomFlags,
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`FilterLoad`] message.
    #[derive(Debug, Clone)]
    pub struct FilterLoadEncoder<'e>(
        Encoder2<
            PrefixedBytesEncoder<'e>,
            Encoder3<
                ArrayEncoder<4>,
                ArrayEncoder<4>,
                BloomFlagsEncoder<'e>
            >
        >
    );
}

impl encoding::Encode for FilterLoad {
    type Encoder<'e> = FilterLoadEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterLoadEncoder::new(Encoder2::new(
            PrefixedBytesEncoder::new(&self.filter),
            Encoder3::new(
                ArrayEncoder::without_length_prefix(self.hash_funcs.to_le_bytes()),
                ArrayEncoder::without_length_prefix(self.tweak.to_le_bytes()),
                self.flags.encoder(),
            ),
        ))
    }
}

type FilterLoadInnerDecoder =
    Decoder4<ByteVecDecoder, ArrayDecoder<4>, ArrayDecoder<4>, BloomFlagsDecoder>;

crate::decoder_newtype! {
    /// The decoder for the [`FilterLoad`] message.
    #[derive(Debug, Default, Clone)]
    pub struct FilterLoadDecoder(FilterLoadInnerDecoder);

    fn end(
        result: Result<
            <FilterLoadInnerDecoder as encoding::Decoder>::Output,
            <FilterLoadInnerDecoder as encoding::Decoder>::Error,
        >
    ) -> Result<FilterLoad, FilterLoadDecoderError> {
        let (filter, hash_funcs, tweak, flags) = result.map_err(FilterLoadDecoderError)?;
        Ok(FilterLoad {
            filter,
            hash_funcs: u32::from_le_bytes(hash_funcs),
            tweak: u32::from_le_bytes(tweak),
            flags,
        })
    }
}

impl encoding::Decode for FilterLoad {
    type Decoder = FilterLoadDecoder;
}

/// Bloom filter update flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BloomFlags {
    /// Never update the filter with outpoints.
    None,
    /// Always update the filter with outpoints.
    All,
    /// Only update the filter with outpoints if it is P2PK or P2MS
    PubkeyOnly,
}

encoding::encoder_newtype_exact! {
    /// The encoder for [`BloomFlags`].
    #[derive(Debug, Clone)]
    pub struct BloomFlagsEncoder<'e>(ArrayEncoder<1>);
}

impl encoding::Encode for BloomFlags {
    type Encoder<'e> = BloomFlagsEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        BloomFlagsEncoder::new(ArrayEncoder::without_length_prefix([match self {
            Self::None => 0,
            Self::All => 1,
            Self::PubkeyOnly => 2,
        }]))
    }
}

type BloomFlagsInnerDecoder = ArrayDecoder<1>;

crate::decoder_newtype! {
    /// The decoder for [`BloomFlags`].
    #[derive(Debug, Default, Clone)]
    pub struct BloomFlagsDecoder(BloomFlagsInnerDecoder);

    fn map_push_bytes_err(err: encoding::UnexpectedEofError) -> BloomFlagsDecoderError {
        BloomFlagsDecoderError::Decoder(err)
    }

    fn end(
        result: Result<[u8; 1], encoding::UnexpectedEofError>
    ) -> Result<BloomFlags, BloomFlagsDecoderError> {
        let bloom_flag_arr = result.map_err(BloomFlagsDecoderError::Decoder)?;
        let bloom_flag = u8::from_le_bytes(bloom_flag_arr);
        Ok(match bloom_flag {
            0 => BloomFlags::None,
            1 => BloomFlags::All,
            2 => BloomFlags::PubkeyOnly,
            flag => return Err(BloomFlagsDecoderError::UnknownFlag(flag)),
        })
    }
}

impl encoding::Decode for BloomFlags {
    type Decoder = BloomFlagsDecoder;
}

/// `filteradd` message updates the current filter with new data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterAdd {
    /// The data element to add to the current filter.
    pub data: Vec<u8>,
}

encoding::encoder_newtype_exact! {
    /// The encoder of the [`FilterAdd`] message.
    #[derive(Debug, Clone)]
    pub struct FilterAddEncoder<'e>(PrefixedBytesEncoder<'e>);
}

impl encoding::Encode for FilterAdd {
    type Encoder<'e> = FilterAddEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterAddEncoder::new(PrefixedBytesEncoder::new(&self.data))
    }
}

type FilterAddInnerDecoder = ByteVecDecoder;

crate::decoder_newtype! {
    /// The decoder for the [`FilterAdd`] message.
    #[derive(Debug, Default, Clone)]
    pub struct FilterAddDecoder(FilterAddInnerDecoder);

    fn end(
        result: Result<Vec<u8>, encoding::ByteVecDecoderError>
    ) -> Result<FilterAdd, FilterAddDecoderError> {
        let data = result.map_err(FilterAddDecoderError)?;
        Ok(FilterAdd { data })
    }
}

impl encoding::Decode for FilterAdd {
    type Decoder = FilterAddDecoder;
}

/// Error types for bloom filter messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// An error occurring when decoding a [`FilterLoad`] message.
    ///
    /// [`FilterLoad`]: super::FilterLoad
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterLoadDecoderError(
        pub(super) <super::FilterLoadInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for FilterLoadDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FilterLoadDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "filterload error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FilterLoadDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error occurring when decoding a [`BloomFlags`].
    ///
    /// [`BloomFlags`]: super::BloomFlags
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BloomFlagsDecoderError {
        /// Inner decoder error.
        Decoder(<super::BloomFlagsInnerDecoder as encoding::Decoder>::Error),
        /// The flag is not known.
        UnknownFlag(u8),
    }

    impl From<Infallible> for BloomFlagsDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for BloomFlagsDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Decoder(d) => write_err!(f, "bloomflags error"; d),
                Self::UnknownFlag(flag) => write!(f, "unknown bloomflag {}", flag),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for BloomFlagsDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Decoder(d) => Some(d),
                Self::UnknownFlag(_f) => None,
            }
        }
    }

    /// An error decoding a [`FilterAdd`] message.
    ///
    /// [`FilterAdd`]: super::FilterAdd
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterAddDecoderError(
        pub(super) <super::FilterAddInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for FilterAddDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FilterAddDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "filteradd error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FilterAddDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BloomFlags {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::None),
            1 => Ok(Self::All),
            _ => Ok(Self::PubkeyOnly),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterAdd {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { data: Vec::<u8>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterLoad {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter: Vec::<u8>::arbitrary(u)?,
            hash_funcs: u.arbitrary()?,
            tweak: u.arbitrary()?,
            flags: u.arbitrary()?,
        })
    }
}
