// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus decoding.

use core::convert::From;
use core::fmt;

use internals::write_err;

use crate::io;
use crate::prelude::*;

/// A decoding error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// And I/O error.
    Io(io::Error),
    /// Tried to allocate an oversized vector.
    OversizedVectorAllocation {
        /// The capacity requested.
        requested: usize,
        /// The maximum capacity.
        max: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The expected checksum.
        expected: [u8; 4],
        /// The invalid checksum.
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way.
    NonMinimalVarInt,
    /// Parsing error.
    ParseFailed(&'static str),
    /// Unsupported Segwit flag.
    UnsupportedSegwitFlag(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write_err!(f, "IO error"; e),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } =>
                write!(f, "allocation of oversized vector: requested {}, maximum {}", r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } =>
                write!(f, "invalid checksum: expected {:x}, actual {:x}", e.as_hex(), a.as_hex()),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::ParseFailed(ref s) => write!(f, "parse failed: {}", s),
            Error::UnsupportedSegwitFlag(ref swflag) =>
                write!(f, "unsupported segwit version: {}", swflag),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Io(e) => Some(e),
            OversizedVectorAllocation { .. }
            | InvalidChecksum { .. }
            | NonMinimalVarInt
            | ParseFailed(_)
            | UnsupportedSegwitFlag(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self { Error::Io(error) }
}
