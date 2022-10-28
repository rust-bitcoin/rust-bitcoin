// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Utility functions.
//!
//! Functions needed by all parts of the Bitcoin library.
//!

pub mod key;
pub mod ecdsa;
pub mod schnorr;
pub mod amount;
pub mod base58;
pub mod hash;
pub mod merkleblock;
pub mod psbt;
pub mod taproot;

use crate::prelude::*;
use crate::io;
use core::fmt;

use bitcoin_internals::write_err;

use crate::consensus::encode;

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Encoding error
    Encode(encode::Error),
    /// The header hash is not below the target
    BlockBadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty
    BlockBadTarget,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Encode(ref e) => write_err!(f, "encoding error"; e),
            Error::BlockBadProofOfWork => f.write_str("block target correct but not attained"),
            Error::BlockBadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Encode(e) => Some(e),
            BlockBadProofOfWork | BlockBadTarget => None
        }
    }
}

#[doc(hidden)]
impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Error {
        Error::Encode(e)
    }
}

// core2 doesn't have read_to_end
pub(crate) fn read_to_end<D: io::Read>(mut d: D) -> Result<Vec<u8>, io::Error> {
    let mut result = vec![];
    let mut buf = [0u8; 64];
    loop {
        match d.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => result.extend_from_slice(&buf[0..n]),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e),
        };
    }
    Ok(result)
}

/// The `address` module now lives at the crate root, re-export everything so as not to break the
/// API, however deprecate the re-exports so folks know to upgrade sooner or later.
#[deprecated(since = "0.30.0", note = "Please use crate::address")]
pub mod address {
    pub use crate::address::*;
}

#[deprecated(since = "0.30.0", note = "Please use crate::bip32")]
pub use crate::bip32;

#[deprecated(since = "0.30.0", note = "Please use crate::bip158")]
pub use crate::bip158;

/// The `misc` module was moved and re-named to `sign_message`.
pub mod misc {
    use crate::prelude::*;

    /// Search for `needle` in the vector `haystack` and remove every
    /// instance of it, returning the number of instances removed.
    /// Loops through the vector opcode by opcode, skipping pushed data.
    // For why we deprecated see: https://github.com/rust-bitcoin/rust-bitcoin/pull/1259#discussion_r968613736
    #[deprecated(since = "0.30.0", note = "No longer supported")]
    pub fn script_find_and_remove(haystack: &mut Vec<u8>, needle: &[u8]) -> usize {
        use crate::blockdata::opcodes;

        if needle.len() > haystack.len() {
            return 0;
        }
        if needle.is_empty() {
            return 0;
        }

        let mut top = haystack.len() - needle.len();
        let mut n_deleted = 0;

        let mut i = 0;
        while i <= top {
            if &haystack[i..(i + needle.len())] == needle {
                for j in i..top {
                    haystack.swap(j + needle.len(), j);
                }
                n_deleted += 1;
                // This is ugly but prevents infinite loop in case of overflow
                let overflow = top < needle.len();
                top = top.wrapping_sub(needle.len());
                if overflow {
                    break;
                }
            } else {
                i += match opcodes::All::from((*haystack)[i]).classify(opcodes::ClassifyContext::Legacy) {
                    opcodes::Class::PushBytes(n) => n as usize + 1,
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => 2,
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => 3,
                    opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => 5,
                    _ => 1
                };
            }
        }
        haystack.truncate(top.wrapping_add(needle.len()));
        n_deleted
    }
}
