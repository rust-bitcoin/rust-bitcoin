// SPDX-License-Identifier: CC0-1.0

//! Test composition of encoders and decoders.

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, BytesEncoder, Decodable, Decoder, Decoder2, Decoder2Error,
    Decoder6, Encodable, Encoder, Encoder2, Encoder3, Encoder6, UnexpectedEofError,
};

const EMPTY: &[u8] = &[];

// A simple composite type that encodes as [4 bytes] + [2 bytes].
#[derive(Debug, PartialEq, Eq)]
struct CompositeData {
    first: [u8; 4],
    second: [u8; 2],
}

impl Encodable for CompositeData {
    type Encoder<'e> = Encoder2<ArrayEncoder<4>, ArrayEncoder<2>>;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            ArrayEncoder::without_length_prefix(self.first),
            ArrayEncoder::without_length_prefix(self.second),
        )
    }
}

/// A unified error type for [`CompositeDataDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompositeError {
    Eof(UnexpectedEofError),
}

impl From<UnexpectedEofError> for CompositeError {
    fn from(eof: UnexpectedEofError) -> Self { Self::Eof(eof) }
}

impl core::fmt::Display for CompositeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Eof(eof) => write!(f, "Composite error: {}", eof),
        }
    }
}

/// A wrapper decoder that converts the tuple output to [`CompositeData`].
struct CompositeDataDecoder {
    inner: Decoder2<ArrayDecoder<4>, ArrayDecoder<2>>,
}

impl CompositeDataDecoder {
    fn new() -> Self {
        Self { inner: Decoder2::new(ArrayDecoder::<4>::new(), ArrayDecoder::<2>::new()) }
    }
}

impl Decoder for CompositeDataDecoder {
    type Output = CompositeData;
    type Error = CompositeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(|error| match error {
            Decoder2Error::First(e) | Decoder2Error::Second(e) => CompositeError::Eof(e),
        })
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (first, second) = self.inner.end().map_err(|error| match error {
            Decoder2Error::First(e) | Decoder2Error::Second(e) => CompositeError::Eof(e),
        })?;
        Ok(CompositeData { first, second })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl Decodable for CompositeData {
    type Decoder = CompositeDataDecoder;

    fn decoder() -> Self::Decoder { CompositeDataDecoder::new() }
}

#[test]
fn composition_chain() {
    let original = CompositeData { first: [0x01, 0x02, 0x03, 0x04], second: [0x05, 0x06] };
    // Encode using the pull encoder.
    let mut encoder = original.encoder();
    let mut encoded_bytes = Vec::new();
    loop {
        encoded_bytes.extend_from_slice(encoder.current_chunk());
        if !encoder.advance() {
            break;
        }
    }
    // Decode using the push decoder.
    let mut decoder = CompositeData::decoder();
    let mut bytes = &encoded_bytes[..];
    let needs_more = decoder.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "CompositeData decoder should be ready to end");
    assert_eq!(bytes, EMPTY);
    let decoded = decoder.end().unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn composition_nested() {
    let data = b"abcdef";
    let mut encoder6 = Encoder6::new(
        ArrayEncoder::without_length_prefix([data[0]]),
        ArrayEncoder::without_length_prefix([data[1]]),
        ArrayEncoder::without_length_prefix([data[2]]),
        ArrayEncoder::without_length_prefix([data[3]]),
        ArrayEncoder::without_length_prefix([data[4]]),
        ArrayEncoder::without_length_prefix([data[5]]),
    );

    let mut encoded_bytes = Vec::new();
    loop {
        encoded_bytes.extend_from_slice(encoder6.current_chunk());
        if !encoder6.advance() {
            break;
        }
    }
    assert_eq!(encoded_bytes, data);

    let mut decoder6: Decoder6<_, _, _, _, _, _> = Decoder6::new(
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
        ArrayDecoder::<1>::new(),
    );
    let mut bytes = &encoded_bytes[..];
    let needs_more = decoder6.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "Decoder6 should be ready to end");
    assert_eq!(bytes, EMPTY);
    let (first, second, third, fourth, fifth, sixth) = decoder6.end().unwrap();
    assert_eq!(first, [data[0]]);
    assert_eq!(second, [data[1]]);
    assert_eq!(third, [data[2]]);
    assert_eq!(fourth, [data[3]]);
    assert_eq!(fifth, [data[4]]);
    assert_eq!(sixth, [data[5]]);
}

#[test]
fn composition_extra_bytes() {
    // Test that Decoder2 consumes exactly what it needs and leaves extra bytes unconsumed.
    let mut decoder2: Decoder2<_, _> =
        Decoder2::new(ArrayDecoder::<2>::new(), ArrayDecoder::<3>::new());
    let mut bytes = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..];
    let original_len = bytes.len();

    let needs_more = decoder2.push_bytes(&mut bytes).unwrap();
    assert!(!needs_more, "Decoder2 should be ready to end after consuming all needed bytes");

    let consumed = original_len - bytes.len();
    assert_eq!(consumed, 5, "Decoder2 should consume exactly 5 bytes");
    assert_eq!(bytes.len(), 3, "3 bytes should remain unconsumed");
    assert_eq!(bytes, &[0x06, 0x07, 0x08], "Remaining bytes should be the last 3");

    let (first, second) = decoder2.end().unwrap();
    assert_eq!(first, [0x01, 0x02], "First decoder should get first 2 bytes");
    assert_eq!(second, [0x03, 0x04, 0x05], "Second decoder should get next 3 bytes");
}

#[test]
#[allow(clippy::too_many_lines)]
fn composition_error_unification() {
    // Demonstrates how decoders unify error types into
    // a single target error type through `From` conversions.

    /// Error for the lower level decoders.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum NestedError {
        BadChecksum,
        UnexpectedEof(UnexpectedEofError),
    }

    impl From<UnexpectedEofError> for NestedError {
        fn from(eof: UnexpectedEofError) -> Self { Self::UnexpectedEof(eof) }
    }

    /// Error for top level encoder.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TopLevelError {
        UnexpectedEof(UnexpectedEofError),
        Validation(NestedError),
    }

    impl From<UnexpectedEofError> for TopLevelError {
        fn from(eof: UnexpectedEofError) -> Self { Self::UnexpectedEof(eof) }
    }

    impl From<NestedError> for TopLevelError {
        fn from(err: NestedError) -> Self {
            match err {
                NestedError::UnexpectedEof(eof) => Self::UnexpectedEof(eof),
                NestedError::BadChecksum => Self::Validation(err),
            }
        }
    }

    /// A test composite decoder.
    struct HeaderDecoder {
        inner: Decoder2<ArrayDecoder<1>, ArrayDecoder<1>>,
    }

    impl HeaderDecoder {
        fn new() -> Self {
            Self { inner: Decoder2::new(ArrayDecoder::<1>::new(), ArrayDecoder::<1>::new()) }
        }
    }

    impl Decoder for HeaderDecoder {
        type Output = ([u8; 1], [u8; 1]);
        type Error = NestedError;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.inner.push_bytes(bytes).map_err(|error| match error {
                Decoder2Error::First(e) | Decoder2Error::Second(e) => NestedError::from(e),
            })
        }

        fn end(self) -> Result<Self::Output, Self::Error> {
            let (first, second) = self.inner.end().map_err(|error| match error {
                Decoder2Error::First(e) | Decoder2Error::Second(e) => NestedError::from(e),
            })?;
            Ok((first, second))
        }

        fn read_limit(&self) -> usize { self.inner.read_limit() }
    }

    /// Another test composite decoder.
    struct PayloadDecoder {
        inner: ArrayDecoder<4>,
    }

    impl PayloadDecoder {
        fn new() -> Self { Self { inner: ArrayDecoder::<4>::new() } }
    }

    impl Decoder for PayloadDecoder {
        type Output = [u8; 4];
        type Error = TopLevelError;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            Ok(self.inner.push_bytes(bytes)?)
        }

        fn end(self) -> Result<Self::Output, Self::Error> {
            let result = self.inner.end()?;
            Ok(result)
        }

        fn read_limit(&self) -> usize { self.inner.read_limit() }
    }

    /// A decoder which can fail.
    struct FailingDecoder {
        inner: ArrayDecoder<1>,
        should_fail: bool,
    }

    impl FailingDecoder {
        fn new(should_fail: bool) -> Self { Self { inner: ArrayDecoder::<1>::new(), should_fail } }
    }

    impl Decoder for FailingDecoder {
        type Output = [u8; 1];
        type Error = NestedError;

        fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
            self.inner.push_bytes(bytes).map_err(NestedError::from)
        }

        fn end(self) -> Result<Self::Output, Self::Error> {
            if self.should_fail {
                Err(NestedError::BadChecksum)
            } else {
                self.inner.end().map_err(NestedError::from)
            }
        }

        fn read_limit(&self) -> usize { self.inner.read_limit() }
    }

    // A multi-layer, nested, decoder structure with a unified top level error type.
    let mut nested_decoder = Decoder6::new(
        HeaderDecoder::new(),
        PayloadDecoder::new(),
        ArrayDecoder::<1>::new(),
        HeaderDecoder::new(),
        PayloadDecoder::new(),
        ArrayDecoder::<2>::new(),
    );

    let test_data = b"abcdefghijklmno";
    let mut bytes = &test_data[..];
    let push_result = nested_decoder.push_bytes(&mut bytes);
    assert!(push_result.is_ok(), "push_bytes should succeed, got error: {:?}", push_result.err());
    let end_result = nested_decoder.end();
    assert!(end_result.is_ok(), "end should succeed, got error: {:?}", end_result.err());

    // Test error during decoding.
    let mut failing_decoder: Decoder2<FailingDecoder, ArrayDecoder<1>> =
        Decoder2::new(FailingDecoder::new(true), ArrayDecoder::<1>::new());
    let test_data = b"ab";
    let mut bytes = &test_data[..];
    let push_result = failing_decoder.push_bytes(&mut bytes);
    assert!(push_result.is_err(), "push_bytes should fail when first decoder fails in end()");
    assert!(
        matches!(push_result.as_ref().unwrap_err(), Decoder2Error::First(NestedError::BadChecksum)),
        "Expected Decoder2Error::First(NestedError::BadChecksum), got {:?}",
        push_result.unwrap_err()
    );
}

#[test]
fn empty_encoders() {
    let bytes = [0x01, 2, 3, 4];
    let mut encoder = Encoder3::new(
        BytesEncoder::without_length_prefix(&bytes[..2]),
        BytesEncoder::without_length_prefix(&[]),
        BytesEncoder::without_length_prefix(&bytes[2..]),
    );

    assert_eq!(encoder.current_chunk(), &[1, 2][..]);
    assert!(encoder.advance());

    // Still have to advance over empty slice.
    assert!(encoder.current_chunk().is_empty());
    assert!(encoder.advance());

    assert_eq!(encoder.current_chunk(), &[3, 4][..]);
    assert!(!encoder.advance());

    // Exhausted.
    assert!(encoder.current_chunk().is_empty());
}
