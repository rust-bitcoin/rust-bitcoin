// SPDX-License-Identifier: CC0-1.0

//! [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md) peer-to-peer feature negotiation.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use encoding::{ByteVecDecoder, Decoder2, Encoder2, PrefixedBytesEncoder};

use self::error::{
    FeatureDataDecoderError, FeatureDataError, FeatureDecoderError, FeatureIdDecoderError,
    FeatureIdError,
};

/// `featureid` field of feature negotiation.
///
/// Normally, this is "BIPXXX" that defines the feature. For more information, see
/// [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md#feature-message).
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeatureId {
    // Guaranteed to always be ASCII.
    feature: String,
}

impl FeatureId {
    /// The advertised feature.
    pub fn as_str(&self) -> &str { &self.feature }
}

impl FromStr for FeatureId {
    type Err = FeatureIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err(FeatureIdError::NotAscii);
        }
        if s.len() < 4 || s.len() > 80 {
            return Err(FeatureIdError::InvalidLength(s.len()));
        }
        Ok(Self { feature: s.into() })
    }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.feature) }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FeatureId`].
    #[derive(Debug, Clone)]
    pub struct FeatureIdEncoder<'e>(
        PrefixedBytesEncoder<'e>
    );
}

impl encoding::Encode for FeatureId {
    type Encoder<'e>
        = FeatureIdEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        FeatureIdEncoder::new(PrefixedBytesEncoder::new(self.feature.as_bytes()))
    }
}

type FeatureIdInnerDecoder = ByteVecDecoder;

/// The decoder type for a [`FeatureId`].
#[derive(Debug, Default, Clone)]
pub struct FeatureIdDecoder(FeatureIdInnerDecoder);

impl encoding::Decoder for FeatureIdDecoder {
    type Output = FeatureId;
    type Error = FeatureIdDecoderError;

    fn read_limit(&self) -> usize { self.0.read_limit() }

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(FeatureIdDecoderError::Decoder)
    }

    fn end(self) -> Result<FeatureId, FeatureIdDecoderError> {
        let feature_id = self.0.end().map_err(FeatureIdDecoderError::Decoder)?;
        let feature_string = String::from_utf8(feature_id)
            .map_err(|_| FeatureIdDecoderError::Malformed(FeatureIdError::NotAscii))?;
        Ok(feature_string.parse().map_err(FeatureIdDecoderError::Malformed)?)
    }
}

impl encoding::Decode for FeatureId {
    type Decoder = FeatureIdDecoder;

    fn decoder() -> Self::Decoder { FeatureIdDecoder(ByteVecDecoder::new_with_limit(80)) }
}

/// `featuredata` field of feature negotiation.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FeatureData {
    data: Vec<u8>,
}

impl FeatureData {
    /// Construct a new feature data.
    ///
    /// # Errors
    ///
    /// If the data is more than 512 bytes. See [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md#feature-message)
    pub fn new(data: Vec<u8>) -> Result<Self, FeatureDataError> {
        if data.len() > 512 {
            return Err(FeatureDataError { too_long: data.len() });
        }
        Ok(Self { data })
    }

    /// Borrow the feature data.
    pub fn data(&self) -> &[u8] { &self.data }

    /// Consume the underlying feature data.
    pub fn into_data(self) -> Vec<u8> { self.data }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FeatureData`].
    #[derive(Debug, Clone)]
    pub struct FeatureDataEncoder<'e>(
        PrefixedBytesEncoder<'e>
    );
}

impl encoding::Encode for FeatureData {
    type Encoder<'e>
        = FeatureDataEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        FeatureDataEncoder::new(PrefixedBytesEncoder::new(&self.data))
    }
}

type FeatureDataInnerDecoder = ByteVecDecoder;

/// The decoder type for a [`FeatureId`].
#[derive(Debug, Default, Clone)]
pub struct FeatureDataDecoder(FeatureDataInnerDecoder);

impl encoding::Decoder for FeatureDataDecoder {
    type Output = FeatureData;
    type Error = FeatureDataDecoderError;

    fn read_limit(&self) -> usize { self.0.read_limit() }

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(FeatureDataDecoderError::Decoder)
    }

    fn end(self) -> Result<FeatureData, FeatureDataDecoderError> {
        let data = self.0.end().map_err(FeatureDataDecoderError::Decoder)?;
        Ok(FeatureData { data })
    }
}

impl encoding::Decode for FeatureData {
    type Decoder = FeatureDataDecoder;

    fn decoder() -> Self::Decoder { FeatureDataDecoder(ByteVecDecoder::new_with_limit(512)) }
}

/// A feature that may be advertised over the peer-to-peer protocol.
///
/// For more information, see [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md#feature-message).
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Feature {
    /// The identifier of the feature.
    pub feature_id: FeatureId,
    /// The data associated with the feature.
    pub feature_data: FeatureData,
}

encoding::encoder_newtype_exact! {
    /// The encoder for a [`Feature`].
    #[derive(Debug, Clone)]
    pub struct FeatureEncoder<'e>(Encoder2<FeatureIdEncoder<'e>, FeatureDataEncoder<'e>>);
}

impl encoding::Encode for Feature {
    type Encoder<'e>
        = FeatureEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        FeatureEncoder::new(Encoder2::new(self.feature_id.encoder(), self.feature_data.encoder()))
    }
}

type FeatureInnerDecoder = Decoder2<FeatureIdDecoder, FeatureDataDecoder>;

crate::decoder_newtype! {
    /// Decoder for [`Feature`].
    #[derive(Debug, Default, Clone)]
    pub struct FeatureDecoder(FeatureInnerDecoder);

    fn end(
        result: Result<(FeatureId, FeatureData), <FeatureInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Feature, FeatureDecoderError> {
        let (feature_id, feature_data) = result.map_err(FeatureDecoderError)?;
        Ok(Feature { feature_id, feature_data })
    }
}

impl encoding::Decode for Feature {
    type Decoder = FeatureDecoder;
}

/// Error types decoding peer features.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    #[cfg(doc)]
    use super::{Feature, FeatureData, FeatureId};

    /// Errors related to a [`FeatureId`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FeatureIdError {
        /// Invalid length for [`FeatureId`].
        InvalidLength(usize),
        /// [`FeatureId`] contains non-ascii characters.
        NotAscii,
    }

    impl From<Infallible> for FeatureIdError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FeatureIdError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match *self {
                Self::InvalidLength(size) => {
                    write!(f, "expected string between 4 and 80 bytes, got {size}.")
                }
                Self::NotAscii => write!(f, "feature id must contain only valid ascii."),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureIdError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidLength(_) => None,
                Self::NotAscii => None,
            }
        }
    }

    /// Errors related to a [`FeatureData`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FeatureDataError {
        /// Data too long.
        pub too_long: usize,
    }

    impl From<Infallible> for FeatureDataError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FeatureDataError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "feature data must be no more than 512 bytes, got {}", self.too_long)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureDataError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
    }

    /// Errors occurring when decoding a [`FeatureId`] message.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FeatureIdDecoderError {
        /// Inner decoder error.
        Decoder(<super::FeatureIdInnerDecoder as encoding::Decoder>::Error),
        /// The [`FeatureId`] is invalid.
        Malformed(FeatureIdError),
    }

    impl From<Infallible> for FeatureIdDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FeatureIdDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Decoder(d) => write_err!(f, "feature id decoder"; d),
                Self::Malformed(e) => write_err!(f, "feature id malformed"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureIdDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Decoder(d) => Some(d),
                Self::Malformed(e) => Some(e),
            }
        }
    }

    /// Errors occurring when decoding a [`FeatureData`] message.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FeatureDataDecoderError {
        /// Inner decoder error.
        Decoder(<super::FeatureDataInnerDecoder as encoding::Decoder>::Error),
        /// The [`FeatureData`] is invalid.
        Malformed(FeatureDataError),
    }

    impl From<Infallible> for FeatureDataDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FeatureDataDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Decoder(d) => write_err!(f, "feature data decoder"; d),
                Self::Malformed(e) => write_err!(f, "feature data malformed"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureDataDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Decoder(d) => Some(d),
                Self::Malformed(e) => Some(e),
            }
        }
    }

    /// Errors occurring when decoding a [`Feature`] message.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FeatureDecoderError(
        pub(super) <super::FeatureInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for FeatureDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for FeatureDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "feature error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}
