// SPDX-License-Identifier: CC0-1.0

//! [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md) peer-to-peer feature negotiation.

use alloc::string::String;
use alloc::vec::Vec;
use core::default::Default;
use core::fmt;
use core::str::{FromStr, Utf8Error};

use encoding::{ByteVecDecoder, Decode, Decoder2, Encoder2, PrefixedBytesEncoder};

use self::error::{
    FeatureDataDecoderError, FeatureDataError, FeatureDecoderError, FeatureIdDecoderError,
    FeatureIdError,
};

/// `featureid` field of feature negotiation.
///
/// Normally, this is "BIPXXX" that defines the feature. For more information, see
/// [BIP-0434](https://github.com/bitcoin/bips/blob/master/bip-0434.md#feature-message).
///
/// BIP-0434 requires the identifier to be between 4 and 80 bytes but only *recommends* that it
/// contain printable ASCII, so the raw bytes are stored and any identifier of a valid length is
/// accepted. Use [`FeatureId::to_str`] to view identifiers that happen to be valid UTF-8.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeatureId {
    feature: Vec<u8>,
}

impl FeatureId {
    /// The minimum length, in bytes, of a [`FeatureId`].
    pub const MIN_LEN: usize = 4;

    /// The maximum length, in bytes, of a [`FeatureId`].
    pub const MAX_LEN: usize = 80;

    /// Constructs a [`FeatureId`] from raw bytes.
    ///
    /// # Errors
    ///
    /// If `feature` is shorter than 4 bytes or longer than 80 bytes.
    pub fn new(feature: Vec<u8>) -> Result<Self, FeatureIdError> {
        if feature.len() < Self::MIN_LEN || feature.len() > Self::MAX_LEN {
            return Err(FeatureIdError::InvalidLength(feature.len()));
        }
        Ok(Self { feature })
    }

    /// The advertised feature as raw bytes.
    pub fn as_bytes(&self) -> &[u8] { &self.feature }

    /// The advertised feature as a string, if it is valid UTF-8.
    ///
    /// BIP-0434 only recommends that the identifier contain printable ASCII, so this returns an
    /// error for identifiers that are still valid on the wire.
    ///
    /// # Errors
    ///
    /// If the identifier is not valid UTF-8.
    pub fn to_str(&self) -> Result<&str, Utf8Error> { core::str::from_utf8(&self.feature) }
}

impl FromStr for FeatureId {
    type Err = FeatureIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::new(s.as_bytes().to_vec()) }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // BIP-0434 only recommends printable ASCII, so the identifier may not be valid UTF-8.
        f.write_str(&String::from_utf8_lossy(&self.feature))
    }
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
        FeatureIdEncoder::new(PrefixedBytesEncoder::new(&self.feature))
    }
}

type FeatureIdInnerDecoder = ByteVecDecoder;

/// The decoder type for a [`FeatureId`].
#[derive(Debug, Clone)]
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
        // BIP-0434 only recommends printable ASCII, so accept any identifier of a valid length.
        FeatureId::new(feature_id).map_err(FeatureIdDecoderError::Malformed)
    }
}

impl encoding::Decode for FeatureId {
    type Decoder = FeatureIdDecoder;

    fn decoder() -> Self::Decoder { FeatureIdDecoder(ByteVecDecoder::new_with_limit(80)) }
}

impl Default for FeatureIdDecoder {
    fn default() -> Self { FeatureId::decoder() }
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
#[derive(Debug, Clone)]
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

impl Default for FeatureDataDecoder {
    fn default() -> Self { FeatureData::decoder() }
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
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FeatureIdError {
        /// Invalid length for [`FeatureId`].
        InvalidLength(usize),
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
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for FeatureIdError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InvalidLength(_) => None,
            }
        }
    }

    /// Errors related to a [`FeatureData`].
    #[derive(Debug, Clone, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use encoding::{decode_from_slice, encode_to_vec};

    use super::*;

    /// The identifier Bitcoin Core uses in its `test_non_ascii_feature_id_accepted` test.
    ///
    /// BIP-0434 requires the `featureid` length to be between 4 and 80 bytes but only *recommends*
    /// printable ASCII, so this is a valid identifier even though it is not valid UTF-8.
    const NON_ASCII_ID: &[u8] = b"\x00\xff\x01\x7f";

    #[test]
    fn feature_id_from_str() {
        let id = FeatureId::from_str("BIP434").unwrap();
        assert_eq!(id.as_bytes(), b"BIP434");
        assert_eq!(id.to_str().unwrap(), "BIP434");
        assert_eq!(id.to_string(), "BIP434");
    }

    #[test]
    fn feature_id_length_boundaries() {
        for len in [FeatureId::MIN_LEN, FeatureId::MAX_LEN] {
            let bytes = vec![b'a'; len];
            let id = FeatureId::new(bytes.clone()).unwrap();
            assert_eq!(id.as_bytes(), bytes.as_slice());
            assert_eq!(FeatureId::from_str(core::str::from_utf8(&bytes).unwrap()).unwrap(), id);
        }

        for len in [0, 1, FeatureId::MIN_LEN - 1, FeatureId::MAX_LEN + 1] {
            let bytes = vec![b'a'; len];
            assert_eq!(FeatureId::new(bytes.clone()), Err(FeatureIdError::InvalidLength(len)));
            assert_eq!(
                FeatureId::from_str(core::str::from_utf8(&bytes).unwrap()),
                Err(FeatureIdError::InvalidLength(len))
            );
        }
    }

    #[test]
    fn feature_id_accepts_non_ascii_bytes() {
        // Regression test for rejecting non-ASCII identifiers. BIP-0434 says SHOULD, not MUST, so
        // this must be accepted. Mirrors Bitcoin Core's `test_non_ascii_feature_id_accepted`.
        let id = FeatureId::new(NON_ASCII_ID.to_vec()).unwrap();
        assert_eq!(id.as_bytes(), NON_ASCII_ID);
        // The identifier is valid on the wire but is not valid UTF-8.
        assert!(id.to_str().is_err());
    }

    #[test]
    fn feature_id_accepts_non_ascii_utf8() {
        // "café" is five bytes and valid UTF-8 but not ASCII.
        let id = FeatureId::from_str("café").unwrap();
        assert_eq!(id.as_bytes(), "café".as_bytes());
        assert_eq!(id.to_str().unwrap(), "café");
    }

    #[test]
    fn feature_id_encode_decode_roundtrip() {
        for bytes in [b"BIP434".to_vec(), NON_ASCII_ID.to_vec()] {
            let id = FeatureId::new(bytes.clone()).unwrap();
            let encoded = encode_to_vec(&id);
            // Compact size length prefix followed by the identifier bytes verbatim.
            assert_eq!(encoded[0], bytes.len() as u8);
            assert_eq!(&encoded[1..], bytes.as_slice());
            assert_eq!(decode_from_slice::<FeatureId>(&encoded).unwrap(), id);
        }
    }

    #[test]
    fn feature_id_decoder_rejects_invalid_length() {
        for len in [0, 1, FeatureId::MIN_LEN - 1, FeatureId::MAX_LEN + 1] {
            let mut encoded = vec![len as u8];
            encoded.extend(vec![b'a'; len]);
            assert!(
                decode_from_slice::<FeatureId>(&encoded).is_err(),
                "identifier of length {len} should not decode"
            );
        }
    }

    #[test]
    fn feature_message_decode_accepts_non_ascii_id() {
        let feature = Feature {
            feature_id: FeatureId::new(NON_ASCII_ID.to_vec()).unwrap(),
            feature_data: FeatureData::new(vec![0xab, 0xcd]).unwrap(),
        };

        let encoded = encode_to_vec(&feature);
        assert_eq!(decode_from_slice::<Feature>(&encoded).unwrap(), feature);
    }
}
