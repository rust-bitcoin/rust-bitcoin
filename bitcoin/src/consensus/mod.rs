// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(feature = "bitcoinconsensus")]
pub mod validation;

use core::fmt;

use internals::write_err;
use io::{BufRead, Read};

use crate::consensus;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt},
    params::Params,
};

#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};

struct IterReader<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> {
    iterator: core::iter::Fuse<I>,
    buf: Option<u8>,
    error: Option<E>,
}

impl<E: fmt::Debug, I: Iterator<Item = Result<u8, E>>> IterReader<E, I> {
    pub(crate) fn new(iterator: I) -> Self {
        IterReader { iterator: iterator.fuse(), buf: None, error: None }
    }

    fn decode<T: Decodable>(mut self) -> Result<T, DecodeError<E>> {
        let result = T::consensus_decode(&mut self);
        match (result, self.error) {
            (Ok(_), None) if self.iterator.next().is_some() => Err(DecodeError::TooManyBytes),
            (Ok(value), None) => Ok(value),
            (Ok(_), Some(error)) => panic!("{} silently ate the error: {:?}", core::any::type_name::<T>(), error),

            (Err(consensus::encode::Error::Io(io_error)), Some(de_error)) if io_error.kind() == io::ErrorKind::Other && io_error.get_ref().is_none() => Err(DecodeError::Other(de_error)),
            (Err(consensus_error), None) => Err(DecodeError::Consensus(consensus_error)),
            (Err(consensus::encode::Error::Io(io_error)), de_error) => panic!("Unexpected IO error {:?} returned from {}::consensus_decode(), deserialization error: {:?}", io_error, core::any::type_name::<T>(), de_error),
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

/// Error when consensus decoding from an `[IterReader]`.
#[derive(Debug)]
pub enum DecodeError<E> {
    /// Attempted to decode an object from an iterator that yielded too many bytes.
    TooManyBytes,
    /// Invalid consensus encoding.
    Consensus(consensus::encode::Error),
    /// Other decoding error.
    Other(E),
}

internals::impl_from_infallible!(DecodeError<E>);

impl<E: fmt::Debug> fmt::Display for DecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeError::*;

        match *self {
            TooManyBytes =>
                write!(f, "attempted to decode object from an iterator that yielded too many bytes"),
            Consensus(ref e) => write_err!(f, "invalid consensus encoding"; e),
            Other(ref other) => write!(f, "other decoding error: {:?}", other),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug> std::error::Error for DecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            TooManyBytes => None,
            Consensus(ref e) => Some(e),
            Other(_) => None, // TODO: Is this correct?
        }
    }
}
