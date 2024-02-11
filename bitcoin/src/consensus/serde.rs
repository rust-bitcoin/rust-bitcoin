// SPDX-License-Identifier: CC0-1.0

//! Serde serialization via consensus encoding
//!
//! This provides functions for (de)serializing any type as consensus-encoded bytes.
//! For human-readable formats it serializes as a string with a consumer-supplied encoding, for
//! binary formats it serializes as a sequence of bytes (not `serialize_bytes` to avoid allocations).
//!
//! The string encoding has to be specified using a marker type implementing the encoding strategy.
//! This crate provides hex encoding via `Hex<Upper>` and `Hex<Lower>`

use core::fmt;
use core::marker::PhantomData;

use io::{BufRead, Read, Write};
use serde::de::{SeqAccess, Unexpected, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};

use super::encode::Error as ConsensusError;
use super::{Decodable, Encodable};

/// Hex-encoding strategy
pub struct Hex<Case = hex::Lower>(PhantomData<Case>)
where
    Case: hex::Case;

impl<C: hex::Case> Default for Hex<C> {
    fn default() -> Self { Hex(Default::default()) }
}

impl<C: hex::Case> ByteEncoder for Hex<C> {
    type Encoder = hex::Encoder<C>;
}

/// Implements hex encoding.
pub mod hex {
    use core::fmt;
    use core::marker::PhantomData;

    use hex::buf_encoder::BufEncoder;

    /// Marker for upper/lower case type-level flags ("type-level enum").
    ///
    /// You may use this trait in bounds only.
    pub trait Case: sealed::Case {}
    impl<T: sealed::Case> Case for T {}

    /// Marker for using lower-case hex encoding.
    pub enum Lower {}
    /// Marker for using upper-case hex encoding.
    pub enum Upper {}

    mod sealed {
        pub trait Case {
            /// Internal detail, don't depend on it!!!
            const INTERNAL_CASE: hex::Case;
        }

        impl Case for super::Lower {
            const INTERNAL_CASE: hex::Case = hex::Case::Lower;
        }

        impl Case for super::Upper {
            const INTERNAL_CASE: hex::Case = hex::Case::Upper;
        }
    }

    // We just guessed at a reasonably sane value.
    const HEX_BUF_SIZE: usize = 512;

    /// Hex byte encoder.
    // We wrap `BufEncoder` to not leak internal representation.
    pub struct Encoder<C: Case>(BufEncoder<[u8; HEX_BUF_SIZE]>, PhantomData<C>);

    impl<C: Case> From<super::Hex<C>> for Encoder<C> {
        fn from(_: super::Hex<C>) -> Self {
            Encoder(BufEncoder::new([0; HEX_BUF_SIZE]), Default::default())
        }
    }

    impl<C: Case> super::EncodeBytes for Encoder<C> {
        fn encode_chunk<W: fmt::Write>(&mut self, writer: &mut W, mut bytes: &[u8]) -> fmt::Result {
            while !bytes.is_empty() {
                if self.0.is_full() {
                    self.flush(writer)?;
                }
                bytes = self.0.put_bytes_min(bytes, C::INTERNAL_CASE);
            }
            Ok(())
        }

        fn flush<W: fmt::Write>(&mut self, writer: &mut W) -> fmt::Result {
            writer.write_str(self.0.as_str())?;
            self.0.clear();
            Ok(())
        }
    }

    // Newtypes to hide internal details.

    /// Error returned when a hex string decoder can't be created.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DecodeInitError(hex::HexToBytesError);

    /// Error returned when a hex string contains invalid characters.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DecodeError(hex::HexToBytesError);

    /// Hex decoder state.
    pub struct Decoder<'a>(hex::HexToBytesIter<'a>);

    impl<'a> Decoder<'a> {
        fn new(s: &'a str) -> Result<Self, DecodeInitError> {
            match hex::HexToBytesIter::new(s) {
                Ok(iter) => Ok(Decoder(iter)),
                Err(error) => Err(DecodeInitError(error)),
            }
        }
    }

    impl<'a> Iterator for Decoder<'a> {
        type Item = Result<u8, DecodeError>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|result| result.map_err(DecodeError))
        }
    }

    impl<'a, C: Case> super::ByteDecoder<'a> for super::Hex<C> {
        type InitError = DecodeInitError;
        type DecodeError = DecodeError;
        type Decoder = Decoder<'a>;

        fn from_str(s: &'a str) -> Result<Self::Decoder, Self::InitError> { Decoder::new(s) }
    }

    impl super::IntoDeError for DecodeInitError {
        fn into_de_error<E: serde::de::Error>(self) -> E {
            use hex::HexToBytesError;

            match self.0 {
                HexToBytesError::OddLengthString(len) =>
                    E::invalid_length(len, &"an even number of ASCII-encoded hex digits"),
                error => panic!("unexpected error: {:?}", error),
            }
        }
    }

    impl super::IntoDeError for DecodeError {
        fn into_de_error<E: serde::de::Error>(self) -> E {
            use hex::HexToBytesError;
            use serde::de::Unexpected;

            const EXPECTED_CHAR: &str = "an ASCII-encoded hex digit";

            match self.0 {
                HexToBytesError::InvalidChar(c) if c.is_ascii() =>
                    E::invalid_value(Unexpected::Char(c as _), &EXPECTED_CHAR),
                HexToBytesError::InvalidChar(c) =>
                    E::invalid_value(Unexpected::Unsigned(c.into()), &EXPECTED_CHAR),
                error => panic!("unexpected error: {:?}", error),
            }
        }
    }
}

struct DisplayWrapper<'a, T: 'a + Encodable, E>(&'a T, PhantomData<E>);

impl<'a, T: 'a + Encodable, E: ByteEncoder> fmt::Display for DisplayWrapper<'a, T, E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut writer = IoWrapper::<'_, _, E::Encoder>::new(f, E::default().into());
        self.0.consensus_encode(&mut writer).map_err(|error| {
            #[cfg(debug_assertions)]
            {
                if error.kind() != io::ErrorKind::Other
                    || error.get_ref().is_some()
                    || !writer.writer.was_error
                {
                    panic!(
                        "{} returned an unexpected error: {:?}",
                        core::any::type_name::<T>(),
                        error
                    );
                }
            }
            fmt::Error
        })?;
        let result = writer.actually_flush();
        if result.is_err() {
            writer.writer.assert_was_error::<E>();
        }
        result
    }
}

struct ErrorTrackingWriter<W: fmt::Write> {
    writer: W,
    #[cfg(debug_assertions)]
    was_error: bool,
}

impl<W: fmt::Write> ErrorTrackingWriter<W> {
    fn new(writer: W) -> Self {
        ErrorTrackingWriter {
            writer,
            #[cfg(debug_assertions)]
            was_error: false,
        }
    }

    #[track_caller]
    fn assert_no_error(&self, fun: &str) {
        #[cfg(debug_assertions)]
        {
            if self.was_error {
                panic!("`{}` called on errored writer", fun);
            }
        }
    }

    fn assert_was_error<Offender>(&self) {
        #[cfg(debug_assertions)]
        {
            if !self.was_error {
                panic!("{} returned an error unexpectedly", core::any::type_name::<Offender>());
            }
        }
    }

    fn set_error(&mut self, was: bool) {
        #[cfg(debug_assertions)]
        {
            self.was_error |= was;
        }
    }

    fn check_err<T, E>(&mut self, result: Result<T, E>) -> Result<T, E> {
        self.set_error(result.is_err());
        result
    }
}

impl<W: fmt::Write> fmt::Write for ErrorTrackingWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.assert_no_error("write_str");
        let result = self.writer.write_str(s);
        self.check_err(result)
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.assert_no_error("write_char");
        let result = self.writer.write_char(c);
        self.check_err(result)
    }
}

struct IoWrapper<'a, W: fmt::Write, E: EncodeBytes> {
    writer: ErrorTrackingWriter<&'a mut W>,
    encoder: E,
}

impl<'a, W: fmt::Write, E: EncodeBytes> IoWrapper<'a, W, E> {
    fn new(writer: &'a mut W, encoder: E) -> Self {
        IoWrapper { writer: ErrorTrackingWriter::new(writer), encoder }
    }

    fn actually_flush(&mut self) -> fmt::Result { self.encoder.flush(&mut self.writer) }
}

impl<'a, W: fmt::Write, E: EncodeBytes> Write for IoWrapper<'a, W, E> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.encoder.encode_chunk(&mut self.writer, bytes) {
            Ok(()) => Ok(bytes.len()),
            Err(fmt::Error) => {
                self.writer.assert_was_error::<E>();
                Err(io::Error::from(io::ErrorKind::Other))
            }
        }
    }
    // we intentionally ignore flushes because we will do a single flush at the end.
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Provides an instance of byte-to-string encoder.
///
/// This is basically a type constructor used in places where value arguments are not accepted.
/// Such as the generic `serialize`.
pub trait ByteEncoder: Default {
    /// The encoder state.
    type Encoder: EncodeBytes + From<Self>;
}

/// Transforms given bytes and writes to the writer.
///
/// The encoder is allowed to be buffered (and probably should be).
/// The design passing writer each time bypasses the need for GAT.
pub trait EncodeBytes {
    /// Transform the provided slice and write to the writer.
    ///
    /// This is similar to the `write_all` method on `io::Write`.
    fn encode_chunk<W: fmt::Write>(&mut self, writer: &mut W, bytes: &[u8]) -> fmt::Result;

    /// Write data in buffer (if any) to the writer.
    fn flush<W: fmt::Write>(&mut self, writer: &mut W) -> fmt::Result;
}

/// Provides an instance of string-to-byte decoder.
///
/// This is basically a type constructor used in places where value arguments are not accepted.
/// Such as the generic `serialize`.
pub trait ByteDecoder<'a> {
    /// Error returned when decoder can't be created.
    ///
    /// This is typically returned when string length is invalid.
    type InitError: IntoDeError + fmt::Debug;

    /// Error returned when decoding fails.
    ///
    /// This is typically returned when the input string contains malformed chars.
    type DecodeError: IntoDeError + fmt::Debug;

    /// The decoder state.
    type Decoder: Iterator<Item = Result<u8, Self::DecodeError>>;

    /// Constructs the decoder from string.
    fn from_str(s: &'a str) -> Result<Self::Decoder, Self::InitError>;
}

/// Converts error into a type implementing `serde::de::Error`
pub trait IntoDeError {
    /// Performs the conversion.
    fn into_de_error<E: serde::de::Error>(self) -> E;
}

struct BinWriter<S: SerializeSeq> {
    serializer: S,
    error: Option<S::Error>,
}

impl<S: SerializeSeq> Write for BinWriter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.write_all(buf).map(|_| buf.len()) }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        for byte in buf {
            if let Err(error) = self.serializer.serialize_element(byte) {
                self.error = Some(error);
                return Err(io::ErrorKind::Other.into());
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct DisplayExpected<D: fmt::Display>(D);

impl<D: fmt::Display> serde::de::Expected for DisplayExpected<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

enum DecodeError<E> {
    TooManyBytes,
    Consensus(ConsensusError),
    Other(E),
}

// not a trait impl because we panic on some variants
fn consensus_error_into_serde<E: serde::de::Error>(error: ConsensusError) -> E {
    match error {
        ConsensusError::Io(error) => panic!("unexpected IO error {:?}", error),
        ConsensusError::OversizedVectorAllocation { requested, max } => E::custom(format_args!(
            "the requested allocation of {} items exceeds maximum of {}",
            requested, max
        )),
        ConsensusError::InvalidChecksum { expected, actual } => E::invalid_value(
            Unexpected::Bytes(&actual),
            &DisplayExpected(format_args!(
                "checksum {:02x}{:02x}{:02x}{:02x}",
                expected[0], expected[1], expected[2], expected[3]
            )),
        ),
        ConsensusError::NonMinimalVarInt =>
            E::custom(format_args!("compact size was not encoded minimally")),
        ConsensusError::ParseFailed(msg) => E::custom(msg),
        ConsensusError::UnsupportedSegwitFlag(flag) =>
            E::invalid_value(Unexpected::Unsigned(flag.into()), &"segwit version 1 flag"),
    }
}

impl<E> DecodeError<E>
where
    E: serde::de::Error,
{
    fn unify(self) -> E {
        match self {
            DecodeError::Other(error) => error,
            DecodeError::TooManyBytes => E::custom(format_args!("got more bytes than expected")),
            DecodeError::Consensus(error) => consensus_error_into_serde(error),
        }
    }
}

impl<E> IntoDeError for DecodeError<E>
where
    E: IntoDeError,
{
    fn into_de_error<DE: serde::de::Error>(self) -> DE {
        match self {
            DecodeError::Other(error) => error.into_de_error(),
            DecodeError::TooManyBytes => DE::custom(format_args!("got more bytes than expected")),
            DecodeError::Consensus(error) => consensus_error_into_serde(error),
        }
    }
}

struct IterReader<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> {
    iterator: core::iter::Fuse<I>,
    buf: Option<u8>,
    error: Option<E>,
}

impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> IterReader<E, I> {
    fn new(iterator: I) -> Self { IterReader { iterator: iterator.fuse(), buf: None, error: None } }

    fn decode<T: Decodable>(mut self) -> Result<T, DecodeError<E>> {
        let result = T::consensus_decode(&mut self);
        match (result, self.error) {
            (Ok(_), None) if self.iterator.next().is_some() => {
                Err(DecodeError::TooManyBytes)
            },
            (Ok(value), None) => Ok(value),
            (Ok(_), Some(error)) => panic!("{} silently ate the error: {:?}", core::any::type_name::<T>(), error),
            (Err(ConsensusError::Io(io_error)), Some(de_error)) if io_error.kind() == io::ErrorKind::Other && io_error.get_ref().is_none() => Err(DecodeError::Other(de_error)),
            (Err(consensus_error), None) => Err(DecodeError::Consensus(consensus_error)),
            (Err(ConsensusError::Io(io_error)), de_error) => panic!("Unexpected IO error {:?} returned from {}::consensus_decode(), deserialization error: {:?}", io_error, core::any::type_name::<T>(), de_error),
            (Err(consensus_error), Some(de_error)) => panic!("{} should've returned `Other` IO error because of deserialization error {:?} but it returned consensus error {:?} instead", core::any::type_name::<T>(), de_error, consensus_error),
        }
    }
}

impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> Read for IterReader<E, I> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut count = 0;
        if buf.is_empty() {
            return Ok(0);
        }

        if let Some(first) = self.buf.take() {
            buf[0] = first;
            buf = &mut buf[1..];
            count += 1;
        }
        for (dst, src) in buf.iter_mut().zip(&mut self.iterator) {
            match src {
                Ok(byte) => *dst = byte,
                Err(error) => {
                    self.error = Some(error);
                    return Err(io::ErrorKind::Other.into());
                }
            }
            // bounded by the length of buf
            count += 1;
        }
        Ok(count)
    }
}

impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> BufRead for IterReader<E, I> {
    fn fill_buf(&mut self) -> Result<&[u8], io::Error> {
        // matching on reference rather than using `ref` confuses borrow checker
        if let Some(ref byte) = self.buf {
            Ok(core::slice::from_ref(byte))
        } else {
            match self.iterator.next() {
                Some(Ok(byte)) => {
                    self.buf = Some(byte);
                    Ok(core::slice::from_ref(self.buf.as_ref().expect("we've just filled it")))
                }
                Some(Err(error)) => {
                    self.error = Some(error);
                    Err(io::ErrorKind::Other.into())
                }
                None => Ok(&[]),
            }
        }
    }

    fn consume(&mut self, len: usize) {
        debug_assert!(len <= 1);
        if len > 0 {
            self.buf = None;
        }
    }
}

/// Helper for `#[serde(with = "")]`.
///
/// To (de)serialize a field using consensus encoding you can write e.g.:
///
/// ```
/// # use actual_serde::{Serialize, Deserialize};
/// use bitcoin::Transaction;
/// use bitcoin::consensus;
///
/// #[derive(Serialize, Deserialize)]
/// # #[serde(crate = "actual_serde")]
/// pub struct MyStruct {
///     #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
///     tx: Transaction,
/// }
/// ```
pub struct With<E>(PhantomData<E>);

impl<E> With<E> {
    /// Serializes the value as consensus-encoded
    pub fn serialize<T: Encodable, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        E: ByteEncoder,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&DisplayWrapper::<'_, _, E>(value, Default::default()))
        } else {
            let serializer = serializer.serialize_seq(None)?;
            let mut writer = BinWriter { serializer, error: None };

            let result = value.consensus_encode(&mut writer);
            match (result, writer.error) {
                (Ok(_), None) => writer.serializer.end(),
                (Ok(_), Some(error)) =>
                    panic!("{} silently ate an IO error: {:?}", core::any::type_name::<T>(), error),
                (Err(io_error), Some(ser_error))
                    if io_error.kind() == io::ErrorKind::Other && io_error.get_ref().is_none() =>
                    Err(ser_error),
                (Err(io_error), ser_error) => panic!(
                    "{} returned an unexpected IO error: {:?} serialization error: {:?}",
                    core::any::type_name::<T>(),
                    io_error,
                    ser_error
                ),
            }
        }
    }

    /// Deserializes the value as consensus-encoded
    pub fn deserialize<'d, T: Decodable, D: Deserializer<'d>>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        for<'a> E: ByteDecoder<'a>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HRVisitor::<_, E>(Default::default()))
        } else {
            deserializer.deserialize_seq(BinVisitor(Default::default()))
        }
    }
}

struct HRVisitor<T: Decodable, D: for<'a> ByteDecoder<'a>>(PhantomData<fn() -> (T, D)>);

impl<'de, T: Decodable, D: for<'a> ByteDecoder<'a>> Visitor<'de> for HRVisitor<T, D> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bytes encoded as a hex string")
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<T, E> {
        let decoder = D::from_str(s).map_err(IntoDeError::into_de_error)?;
        IterReader::new(decoder).decode().map_err(IntoDeError::into_de_error)
    }
}

struct BinVisitor<T: Decodable>(PhantomData<fn() -> T>);

impl<'de, T: Decodable> Visitor<'de> for BinVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, s: S) -> Result<T, S::Error> {
        IterReader::new(SeqIterator(s, Default::default())).decode().map_err(DecodeError::unify)
    }
}

struct SeqIterator<'a, S: serde::de::SeqAccess<'a>>(S, PhantomData<&'a ()>);

impl<'a, S: serde::de::SeqAccess<'a>> Iterator for SeqIterator<'a, S> {
    type Item = Result<u8, S::Error>;

    fn next(&mut self) -> Option<Self::Item> { self.0.next_element::<u8>().transpose() }
}
