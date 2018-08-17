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

//! Utility functions
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

use std::{error, fmt};

use secp256k1;

use network;
use network::serialize;

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
    /// The `target` field of a block header did not match the expected difficulty
    SpvBadTarget,
    /// The header hash is not below the target
    SpvBadProofOfWork,
    /// secp-related error
    Secp256k1(secp256k1::Error),
    /// Serialization error
    Serialize(serialize::Error),
    /// Network error
    Network(network::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp256k1(ref e) => fmt::Display::fmt(e, f),
            Error::Serialize(ref e) => fmt::Display::fmt(e, f),
            ref x => f.write_str(error::Error::description(x))
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Secp256k1(ref e) => Some(e),
            Error::Serialize(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Secp256k1(ref e) => e.description(),
            Error::SpvBadTarget => "target incorrect",
            Error::SpvBadProofOfWork => "target correct but not attained",
            Error::Serialize(ref e) => e.description(),
            Error::Network(ref e) => e.description(),
        }
    }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

#[doc(hidden)]
impl From<serialize::Error> for Error {
    fn from(e: serialize::Error) -> Error {
        Error::Serialize(e)
    }
}

#[doc(hidden)]
impl From<network::Error> for Error {
    fn from(e: network::Error) -> Error {
        Error::Network(e)
    }
}
