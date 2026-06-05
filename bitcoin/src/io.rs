// SPDX-License-Identifier: CC0-1.0

//! Minimal `std::io` replacement for `no-std` builds.
//!
//! `std::io` is not available without `std`, and the crate that used to provide the polyfill
//! (`core2`) has had every published version yanked, so depending on it breaks the build for
//! everyone, `std` users included. Later `rust-bitcoin` releases solved this with a dedicated
//! `bitcoin-io` crate, but that crate raises the MSRV and is only wired into newer `hashes` and
//! `hex-conservative` releases, so it cannot be adopted on this branch without a breaking
//! dependency bump.
//!
//! This module is therefore an inlined copy of `bitcoin-io` (the `io` crate at version 0.1.1,
//! originally written by Matt Corallo, CC0-1.0). It is trimmed to the single configuration this
//! crate compiles it under: `no-std` with `alloc`, never `std` (when `std` is enabled the `io`
//! name resolves to `std::io` and this module is not compiled). The `BufRead` trait and the
//! `std`-only conversions from the upstream file are dropped because nothing here uses them. The
//! `StdError` shim and the `impl_write_for_engine!` block at the end are local additions, see the
//! comments there.

use crate::prelude::*;
use core::convert::TryInto;
use core::fmt::{self, Debug, Display, Formatter};
use core::{cmp, result};

/// Result type returned by functions in this module.
pub type Result<T> = result::Result<T, Error>;

/// The `io` error type.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    error: Option<Box<dyn Debug + Send + Sync + 'static>>,
}

impl Error {
    /// Creates a new I/O error from a known kind and an arbitrary payload.
    pub fn new<E: sealed::IntoBoxDynDebug>(kind: ErrorKind, error: E) -> Error {
        Error { kind, error: Some(error.into()) }
    }

    /// Returns the error kind for this error.
    pub fn kind(&self) -> ErrorKind { self.kind }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error { Error { kind, error: None } }
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("I/O Error: {}", self.kind.description()))?;
        if let Some(e) = &self.error {
            fmt.write_fmt(format_args!(". {:?}", e))?;
        }
        Ok(())
    }
}

macro_rules! define_errorkind {
    ($($(#[$($attr:tt)*])* $kind:ident),* $(,)?) => {
        /// A minimal subset of [`std::io::ErrorKind`] which is used for [`Error`]. Note that, as
        /// with [`std::io`], only [`Self::Interrupted`] has defined semantics here, all other
        /// variants exist only so that callers can construct the same errors they would against
        /// `std::io`.
        #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
        pub enum ErrorKind {
            $(
                $(#[$($attr)*])*
                $kind,
            )*
        }

        impl ErrorKind {
            fn description(&self) -> &'static str {
                match self {
                    $(ErrorKind::$kind => stringify!($kind),)*
                }
            }
        }
    }
}

define_errorkind! {
    /// An entity was not found, often a file.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// The connection was refused by the remote server.
    ConnectionRefused,
    /// The connection was reset by the remote server.
    ConnectionReset,
    /// The connection was aborted (terminated) by the remote server.
    ConnectionAborted,
    /// The network operation failed because it was not connected yet.
    NotConnected,
    /// A socket address could not be bound because the address is already in use elsewhere.
    AddrInUse,
    /// A nonexistent interface was requested or the requested address was not local.
    AddrNotAvailable,
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// The operation needs to block to complete, but the blocking operation was requested to not occur.
    WouldBlock,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    InvalidData,
    /// The I/O operation's timeout expired, causing it to be canceled.
    TimedOut,
    /// A call to `write` returned `Ok(0)`.
    WriteZero,
    /// This operation was interrupted.
    Interrupted,
    /// An "end of file" was reached prematurely.
    UnexpectedEof,
    /// A custom error that does not fall under any other I/O error kind.
    Other,
}

/// A generic trait describing an input stream. See [`std::io::Read`] for more info.
pub trait Read {
    /// Reads bytes from source into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Reads bytes from source until `buf` is full.
    #[inline]
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(len) => buf = &mut buf[len..],
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Creates an adapter which will read at most `limit` bytes.
    #[inline]
    fn take(&mut self, limit: u64) -> Take<'_, Self> { Take { reader: self, remaining: limit } }

    /// Returns a mutable reference to `self`.
    // Provided here (not in upstream `bitcoin-io`) because this crate's consensus decoding calls
    // `by_ref` to reborrow readers, which `std::io::Read` and `core2` offered.
    #[inline]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

// Provided here (not in upstream `bitcoin-io`) because this crate passes `&mut reader` to functions
// that are generic over `Read`; `std::io` and `core2` carried these blanket impls.
impl<R: Read + ?Sized> Read for &mut R {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> { (**self).read(buf) }
}

impl Read for &[u8] {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let cnt = cmp::min(self.len(), buf.len());
        buf[..cnt].copy_from_slice(&self[..cnt]);
        *self = &self[cnt..];
        Ok(cnt)
    }
}

/// Reader adapter which limits the bytes read from an underlying reader.
///
/// Created by calling [`Read::take`].
pub struct Take<'a, R: Read + ?Sized> {
    reader: &'a mut R,
    remaining: u64,
}

impl<'a, R: Read + ?Sized> Read for Take<'a, R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = cmp::min(buf.len(), self.remaining.try_into().unwrap_or(buf.len()));
        let read = self.reader.read(&mut buf[..len])?;
        self.remaining -= read.try_into().unwrap_or(self.remaining);
        Ok(read)
    }
}

/// Wraps an in memory reader providing the `position` function.
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T: AsRef<[u8]>> Cursor<T> {
    /// Creates a `Cursor` by wrapping `inner`.
    #[inline]
    pub fn new(inner: T) -> Self { Cursor { inner, pos: 0 } }

    /// Returns the position read up to thus far.
    #[inline]
    pub fn position(&self) -> u64 { self.pos }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let inner: &[u8] = self.inner.as_ref();
        let start_pos = self.pos.try_into().unwrap_or(inner.len());
        let read = cmp::min(inner.len().saturating_sub(start_pos), buf.len());
        buf[..read].copy_from_slice(&inner[start_pos..start_pos + read]);
        self.pos =
            self.pos.saturating_add(read.try_into().unwrap_or(u64::max_value() /* unreachable */));
        Ok(read)
    }
}

/// A generic trait describing an output stream. See [`std::io::Write`] for more info.
pub trait Write {
    /// Writes `buf` into this writer, returning how many bytes were written.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flushes this output stream, ensuring that all intermediately buffered contents
    /// reach their destination.
    fn flush(&mut self) -> Result<()>;

    /// Attempts to write an entire buffer into this writer.
    #[inline]
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(len) => buf = &buf[len..],
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// Provided here (not in upstream `bitcoin-io`) because this crate passes `&mut writer` to functions
// that are generic over `Write`; `std::io` and `core2` carried these blanket impls.
impl<W: Write + ?Sized> Write for &mut W {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { (**self).write(buf) }
    #[inline]
    fn flush(&mut self) -> Result<()> { (**self).flush() }
}

impl Write for alloc::vec::Vec<u8> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

impl Write for &mut [u8] {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let cnt = cmp::min(self.len(), buf.len());
        self[..cnt].copy_from_slice(&buf[..cnt]);
        *self = &mut core::mem::take(self)[cnt..];
        Ok(cnt)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

/// A sink to which all writes succeed. See [`std::io::Sink`] for more info.
///
/// Created using [`sink`].
pub struct Sink;

impl Write for Sink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }

    #[inline]
    fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }

    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

/// Returns a sink to which all writes succeed. See [`std::io::sink`] for more info.
#[inline]
pub fn sink() -> Sink { Sink }

// --- Local additions, not part of upstream `bitcoin-io` ---

/// Stand-in for `std::error::Error` in `no-std` builds.
///
/// `bitcoin-io` lets `std::error::Error` carry this role under `std`; with `std` off there is no
/// such trait, so this crate imports this shim through the crate root as `StdError` and the same
/// call sites work under both configurations. Only `source` is used, by the consensus serde code.
pub trait StdError: Debug {
    /// Returns the lower-level source of this error, if any.
    #[allow(dead_code)]
    fn source(&self) -> Option<&(dyn StdError + 'static)> { None }
}

impl StdError for Error {}

// `bitcoin_hashes` 0.13 only implements `io::Write` for its engines against `std::io` or
// `core2::io`. With `std` off and `core2` gone we provide the impls here so that hashing through
// `consensus_encode` keeps working. Hashing never fails, so these always return `Ok`.
macro_rules! impl_write_for_engine {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Write for $ty {
                #[inline]
                fn write(&mut self, buf: &[u8]) -> Result<usize> {
                    hashes::HashEngine::input(self, buf);
                    Ok(buf.len())
                }
                #[inline]
                fn flush(&mut self) -> Result<()> { Ok(()) }
            }
        )*
    }
}

impl_write_for_engine! {
    hashes::sha1::HashEngine,
    hashes::sha256::HashEngine,
    hashes::sha512::HashEngine,
    hashes::ripemd160::HashEngine,
    hashes::siphash24::HashEngine,
}

impl<T: hashes::Hash> Write for hashes::hmac::HmacEngine<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        hashes::HashEngine::input(self, buf);
        Ok(buf.len())
    }
    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

mod sealed {
    use crate::prelude::*;
    use core::fmt::Debug;

    /// Payloads that can be stored inside an [`super::Error`].
    pub trait IntoBoxDynDebug {
        /// Boxes `self` as a `dyn Debug` error payload.
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static>;
    }

    impl IntoBoxDynDebug for &str {
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(String::from(self)) }
    }

    impl IntoBoxDynDebug for String {
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(self) }
    }
}
