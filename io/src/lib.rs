//! Rust-Bitcoin IO Library
//!
//! Because the core `std::io` module is not yet exposed in `no-std` Rust, building `no-std`
//! applications which require reading and writing objects via standard traits is not generally
//! possible. While there is ongoing work to improve this situation, this module is not likely to
//! be available for applications with broad rustc version support for some time.
//!
//! Thus, this library exists to export a minmal version of `std::io`'s traits which `no-std`
//! applications may need. With the `std` feature, these traits are also implemented for the
//! `std::io` traits, allowing standard objects to be used wherever the traits from this crate are
//! required.
//!
//! This traits are not one-for-one drop-ins, but are as close as possible while still implementing
//! `std::io`'s traits without unnecessary complexity.

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

/// Standard I/O stream definitions which are API-equivalent to `std`'s `io` module. See
/// [`std::io`] for more info.
pub mod io {
    #[cfg(any(feature = "alloc", feature = "std"))]
    use alloc::boxed::Box;
    use core::convert::TryInto;
    use core::fmt::{Debug, Display, Formatter};

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    mod sealed {
        use alloc::boxed::Box;
        use alloc::string::String;
        use core::fmt::Debug;
        pub trait IntoBoxDynDebug {
            fn into(self) -> Box<dyn Debug + Send + Sync + 'static>;
        }
        impl IntoBoxDynDebug for &str {
            fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(String::from(self)) }
        }
        impl IntoBoxDynDebug for String {
            fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(self) }
        }
    }

    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,

        #[cfg(feature = "std")]
        error: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
        #[cfg(all(feature = "alloc", not(feature = "std")))]
        error: Option<Box<dyn Debug + Send + Sync + 'static>>,
    }
    impl Error {
        #[cfg(feature = "std")]
        pub fn new<E>(kind: ErrorKind, error: E) -> Error
        where
            E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
        {
            Self { kind, error: Some(error.into()) }
        }
        #[cfg(all(feature = "alloc", not(feature = "std")))]
        pub fn new<E: sealed::IntoBoxDynDebug>(kind: ErrorKind, error: E) -> Error {
            Self { kind, error: Some(error.into()) }
        }

        pub fn kind(&self) -> ErrorKind { self.kind }
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Error {
            Self {
                kind,
                #[cfg(any(feature = "std", feature = "alloc"))]
                error: None,
            }
        }
    }

    impl Display for Error {
        fn fmt(&self, fmt: &mut Formatter) -> core::result::Result<(), core::fmt::Error> {
            fmt.write_fmt(format_args!("I/O Error: {}", self.kind.description()))?;
            #[cfg(any(feature = "alloc", feature = "std"))]
            if let Some(e) = &self.error {
                fmt.write_fmt(format_args!(". {:?}", e))?;
            }
            Ok(())
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.error.as_ref().and_then(|e| e.as_ref().source())
        }
        #[allow(deprecated)]
        fn description(&self) -> &str {
            match self.error.as_ref() {
                Some(e) => e.description(),
                None => self.kind.description(),
            }
        }
        #[allow(deprecated)]
        fn cause(&self) -> Option<&dyn std::error::Error> {
            self.error.as_ref().and_then(|e| e.as_ref().cause())
        }
    }

    impl Error {
        #[cfg(feature = "std")]
        pub fn get_ref(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
            self.error.as_deref()
        }
        #[cfg(all(feature = "alloc", not(feature = "std")))]
        pub fn get_ref(&self) -> Option<&(dyn Debug + Send + Sync + 'static)> {
            self.error.as_deref()
        }
    }

    #[cfg(feature = "std")]
    impl From<std::io::Error> for Error {
        fn from(o: std::io::Error) -> Error {
            Self { kind: ErrorKind::from_std(o.kind()), error: o.into_inner() }
        }
    }

    #[cfg(feature = "std")]
    impl From<Error> for std::io::Error {
        fn from(o: Error) -> std::io::Error {
            if let Some(err) = o.error {
                std::io::Error::new(o.kind.to_std(), err)
            } else {
                o.kind.to_std().into()
            }
        }
    }

    macro_rules! define_errorkind {
        ($($kind: ident),*) => {
            #[non_exhaustive]
            #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
            /// A minimal subset of [`std::io::ErrorKind`] which is used for [`Error`]. Note that, as with
            /// [`std::io`], only [`Self::Interrupted`] has defined semantics in this crate, all other
            /// variants are provided here only to provide higher-fidelity conversions to and from
            /// [`std::io::Error`].
            pub enum ErrorKind {
                $($kind),*
            }

            impl ErrorKind {
                fn description(&self) -> &'static str {
                    match self {
                        $(Self::$kind => stringify!($kind)),*
                    }
                }
                #[cfg(feature = "std")]
                fn to_std(self) -> std::io::ErrorKind {
                    match self {
                        $(Self::$kind => std::io::ErrorKind::$kind),*
                    }
                }
                #[cfg(feature = "std")]
                fn from_std(o: std::io::ErrorKind) -> ErrorKind {
                    match o {
                        $(std::io::ErrorKind::$kind => ErrorKind::$kind),*,
                        _ => ErrorKind::Other
                    }
                }
            }
        }
    }

    define_errorkind!(
        NotFound,
        PermissionDenied,
        ConnectionRefused,
        ConnectionReset,
        ConnectionAborted,
        NotConnected,
        AddrInUse,
        AddrNotAvailable,
        BrokenPipe,
        AlreadyExists,
        WouldBlock,
        InvalidInput,
        InvalidData,
        TimedOut,
        WriteZero,
        Interrupted,
        UnexpectedEof,
        // Note: Any time we bump the MSRV any new error kinds should be added here!
        Other
    );

    pub type Result<T> = core::result::Result<T, Error>;

    /// A generic trait describing an input stream. See [`std::io::Read`] for more info.
    pub trait Read {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
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
        #[inline]
        fn take(&mut self, limit: u64) -> Take<Self> { Take { reader: self, remaining: limit } }
    }

    pub struct Take<'a, R: Read + ?Sized> {
        reader: &'a mut R,
        remaining: u64,
    }
    impl<'a, R: Read + ?Sized> Read for Take<'a, R> {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let len = core::cmp::min(buf.len(), self.remaining.try_into().unwrap_or(buf.len()));
            let read = self.reader.read(&mut buf[..len])?;
            self.remaining -= read.try_into().unwrap_or(self.remaining);
            Ok(read)
        }
    }

    #[cfg(feature = "std")]
    impl<R: std::io::Read> Read for R {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            Ok(<R as std::io::Read>::read(self, buf)?)
        }
    }

    #[cfg(not(feature = "std"))]
    impl Read for &[u8] {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let cnt = core::cmp::min(self.len(), buf.len());
            buf[..cnt].copy_from_slice(&self[..cnt]);
            *self = &self[cnt..];
            Ok(cnt)
        }
    }

    pub struct Cursor<T> {
        inner: T,
        pos: u64,
    }
    impl<T: AsRef<[u8]>> Cursor<T> {
        #[inline]
        pub fn new(inner: T) -> Self { Cursor { inner, pos: 0 } }
        #[inline]
        pub fn position(&self) -> u64 { self.pos }
        #[inline]
        pub fn into_inner(self) -> T { self.inner }
    }
    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let inner: &[u8] = self.inner.as_ref();
            let start_pos = self.pos.try_into().unwrap_or(inner.len());
            let read = core::cmp::min(inner.len().saturating_sub(start_pos), buf.len());
            buf[..read].copy_from_slice(&inner[start_pos..start_pos + read]);
            self.pos = self
                .pos
                .saturating_add(read.try_into().unwrap_or(u64::max_value() /* unreachable */));
            Ok(read)
        }
    }

    /// A generic trait describing an output stream. See [`std::io::Write`] for more info.
    pub trait Write {
        fn write(&mut self, buf: &[u8]) -> Result<usize>;
        fn flush(&mut self) -> Result<()>;

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

    #[cfg(feature = "std")]
    impl<W: std::io::Write> Write for W {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(<W as std::io::Write>::write(self, buf)?)
        }
        #[inline]
        fn flush(&mut self) -> Result<()> { Ok(<W as std::io::Write>::flush(self)?) }
    }

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    impl Write for alloc::vec::Vec<u8> {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.extend_from_slice(buf);
            Ok(buf.len())
        }
        #[inline]
        fn flush(&mut self) -> Result<()> { Ok(()) }
    }

    #[cfg(not(feature = "std"))]
    impl<'a> Write for &'a mut [u8] {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let cnt = core::cmp::min(self.len(), buf.len());
            self[..cnt].copy_from_slice(&buf[..cnt]);
            *self = &mut core::mem::take(self)[cnt..];
            Ok(cnt)
        }
        #[inline]
        fn flush(&mut self) -> Result<()> { Ok(()) }
    }

    /// A sink to which all writes succeed. See [`std::io::Sink`] for more info.
    pub struct Sink;
    #[cfg(not(feature = "std"))]
    impl Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }
        #[inline]
        fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }
        #[inline]
        fn flush(&mut self) -> Result<()> { Ok(()) }
    }
    #[cfg(feature = "std")]
    impl std::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { Ok(buf.len()) }
        #[inline]
        fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> { Ok(()) }
        #[inline]
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    /// Returns a sink to which all writes succeed. See [`std::io::sink`] for more info.
    pub fn sink() -> Sink { Sink }
}

#[doc(hidden)]
#[cfg(feature = "std")]
/// Re-export std for the below macro
pub use std as _std;

#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` for users using
/// that feature. In any case, this crate's `io::Write` feature will be implemented for the given
/// type, even if indirectly.
#[cfg(not(feature = "std"))]
macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        impl<$($bounded_ty: $bounds),*> $crate::io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> $crate::io::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> $crate::io::Result<()> {
                $flush_fn(self)
            }
        }
    }
}

#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` for users using
/// that feature. In any case, this crate's `io::Write` feature will be implemented for the given
/// type, even if indirectly.
#[cfg(feature = "std")]
macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        impl<$($bounded_ty: $bounds),*> $crate::_std::io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> $crate::_std::io::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> $crate::_std::io::Result<()> {
                $flush_fn(self)
            }
        }
    }
}
