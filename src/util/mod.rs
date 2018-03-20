// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Utility functions
//!
//! Functions needed by all parts of the Bitcoin library

pub mod privkey;
pub mod address;
pub mod base58;
pub mod bip32;
pub mod bip143;
pub mod contracthash;
pub mod decimal;
pub mod hash;
pub mod iter;
pub mod misc;
pub mod uint;

#[cfg(feature = "fuzztarget")]
pub mod sha2;

use std::{error, fmt, io};

use bitcoin_bech32;
use secp256k1;

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;

    /// Create all-zeros value
    fn zero() -> Self;

    /// Create value represeting one
    fn one() -> Self;
}

/// A general error code
#[derive(Debug)]
pub enum Error {
    /// An I/O error
    Io(io::Error),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Bech32 encoding error
    Bech32(bitcoin_bech32::Error),
    /// Error from the `byteorder` crate
    ByteOrder(io::Error),
    /// Network magic was not what we expected
    BadNetworkMagic(u32, u32),
    /// Network message was unrecognized
    BadNetworkMessage(String),
    /// An object was attempted to be added twice
    DuplicateHash,
    /// Some operation was attempted on a block (or blockheader) that doesn't exist
    BlockNotFound,
    /// Parsing error
    ParseFailed,
    /// An object was added but it does not link into existing history
    PrevHashNotFound,
    /// secp-related error
    Secp256k1(secp256k1::Error),
    /// The `target` field of a block header did not match the expected difficulty
    SpvBadTarget,
    /// The header hash is not below the target
    SpvBadProofOfWork,
    /// Error propagated from subsystem
    Detail(String, Box<Error>),
    /// Unsupported witness version
    UnsupportedWitnessVersion(u8)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::Base58(ref e) => fmt::Display::fmt(e, f),
            Error::Bech32(ref e) => fmt::Display::fmt(e, f),
            Error::ByteOrder(ref e) => fmt::Display::fmt(e, f),
            Error::BadNetworkMagic(exp, got) => write!(f, "expected network magic 0x{:x}, got 0x{:x}", exp, got),
            Error::BadNetworkMessage(ref got) => write!(f, "incorrect network message {}", got),
            Error::Detail(ref s, ref e) => write!(f, "{}: {}", s, e),
            Error::Secp256k1(ref e) => fmt::Display::fmt(e, f),
            ref x => f.write_str(error::Error::description(x))
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Base58(ref e) => Some(e),
            Error::Bech32(ref e) => Some(e),
            Error::ByteOrder(ref e) => Some(e),
            Error::Detail(_, ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Io(ref e) => e.description(),
            Error::Base58(ref e) => e.description(),
            Error::Bech32(ref e) => e.description(),
            Error::ByteOrder(ref e) => e.description(),
            Error::BadNetworkMagic(_, _) => "incorrect network magic",
            Error::BadNetworkMessage(_) => "incorrect/unexpected network message",
            Error::DuplicateHash => "duplicate hash",
            Error::BlockNotFound => "no such block",
            Error::ParseFailed => "parsing error",
            Error::PrevHashNotFound => "prevhash not found",
            Error::Secp256k1(ref e) => e.description(),
            Error::SpvBadTarget => "target incorrect",
            Error::SpvBadProofOfWork => "target correct but not attained",
            Error::Detail(_, ref e) => e.description(),
            Error::UnsupportedWitnessVersion(_) => "unsupported witness version"
        }
    }
}

/// Prepend the detail of an `IoResult`'s error with some text to get poor man's backtracing
pub fn propagate_err<T>(s: String, res: Result<T, Error>) -> Result<T, Error> {
    res.map_err(|err| Error::Detail(s, Box::new(err)))
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

impl From<bitcoin_bech32::Error> for Error {
    fn from(e: bitcoin_bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

