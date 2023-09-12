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
//!
//! Further, with the `core2` feature, if the `std` feature is not set, the crate traits will be
//! implemented for `core2`'s `io` traits as well.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), not(feature = "core2")))]
compile_error!("At least one of std or core2 must be enabled");

#[cfg(feature = "std")]
pub use std::error;
#[cfg(not(feature = "std"))]
pub use core2::error;

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

/// Standard I/O stream definitions which are API-equivalent to `std`'s `io` module. See
/// [`std::io`] for more info.
pub mod io {
    use core::convert::TryInto;

    #[cfg(all(not(feature = "std"), not(feature = "core2")))]
    compile_error!("At least one of std or core2 must be enabled");

    #[cfg(feature = "std")]
    pub use std::io::{Cursor, Error, ErrorKind, Result};

    #[cfg(not(feature = "std"))]
    pub use core2::io::{Cursor, Error, ErrorKind, Result};

    /// A generic trait describing an input stream. See [`std::io::Read`] for more info.
    pub trait Read {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
        #[inline]
        fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.read(buf) {
                    Ok(0) =>
                        return Err(Error::new(ErrorKind::UnexpectedEof, "")),
                    Ok(len) => {
                        buf = &mut buf[len..];
                    },
                    Err(e) if e.kind() == ErrorKind::Interrupted => {},
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
        #[inline]
        fn take(&mut self, limit: u64) -> Take<Self> {
            Take { reader: self, remaining: limit }
        }
        #[inline]
        #[cfg(any(feature = "alloc", feature = "std"))]
        fn read_to_end(&mut self, buf: &mut alloc::vec::Vec<u8>) -> Result<usize> {
            let mut bytes_read = 0;
            let mut read_buf = [0u8; 512];
            loop {
                match self.read(&mut read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&read_buf[0..n]);
                        bytes_read += n;
                    },
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(bytes_read)
        }
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
            <R as std::io::Read>::read(self, buf)
        }
    }

    #[cfg(all(feature = "core2", not(feature = "std")))]
    impl<R: core2::io::Read> Read for R {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            <R as core2::io::Read>::read(self, buf)
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
                    Ok(0) =>
                        return Err(Error::new(ErrorKind::UnexpectedEof, "")),
                    Ok(len) => {
                        buf = &buf[len..];
                    },
                    Err(e) if e.kind() == ErrorKind::Interrupted => {},
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
            <W as std::io::Write>::write(self, buf)
        }
        #[inline]
        fn flush(&mut self) -> Result<()> {
            <W as std::io::Write>::flush(self)
        }
    }

    #[cfg(all(feature = "core2", not(feature = "std")))]
    impl<W: core2::io::Write> Write for W {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            <W as core2::io::Write>::write(self, buf)
        }
        #[inline]
        fn flush(&mut self) -> Result<()> {
            <W as core2::io::Write>::flush(self)
        }
    }

    /// A sink to which all writes succeed. See [`std::io::Sink`] for more info.
    pub struct Sink;
    #[cfg(not(any(feature = "core2", feature = "std")))]
    impl Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(buf.len())
        }
        #[inline]
        fn write_all(&mut self, _: &[u8]) -> Result<()> { Ok(()) }
        #[inline]
        fn flush(&mut self) -> Result<()> { Ok(()) }
    }
    #[cfg(feature = "std")]
    impl std::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        #[inline]
        fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> { Ok(()) }
        #[inline]
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    #[cfg(all(feature = "core2", not(feature = "std")))]
    impl core2::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
            Ok(buf.len())
        }
        #[inline]
        fn write_all(&mut self, _: &[u8]) -> core2::io::Result<()> { Ok(()) }
        #[inline]
        fn flush(&mut self) -> core2::io::Result<()> { Ok(()) }
    }
    /// Returns a sink to which all writes succeed. See [`std::io::sink`] for more info.
    pub fn sink() -> Sink { Sink }
}

#[doc(hidden)]
#[cfg(feature = "core2")]
/// Re-export core2 for the below macro
pub use core2 as _core2;

#[doc(hidden)]
#[cfg(feature = "std")]
/// Re-export std for the below macro
pub use std as _std;

#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` or `core2` for
/// users using those features. In any case, this crate's `io::Write` feature will be implemented
/// for the given type, even if indirectly.
#[cfg(not(any(feature = "core2", feature = "std")))]
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
/// crate's native `io::Write` trait directly, or a more generic trait from `std` or `core2` for
/// users using those features. In any case, this crate's `io::Write` feature will be implemented
/// for the given type, even if indirectly.
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


#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` or `core2` for
/// users using those features. In any case, this crate's `io::Write` feature will be implemented
/// for the given type, even if indirectly.
#[cfg(all(feature = "core2", not(feature = "std")))]
macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        impl<$($bounded_ty: $bounds),*> $crate::_core2::io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> $crate::_core2::io::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> $crate::_core2::io::Result<()> {
                $flush_fn(self)
            }
        }
    }
}
