//! The segregated witness program as defined by [BIP141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::convert::TryInto;
use core::fmt;

use crate::blockdata::script::witness_version::WitnessVersion;
use crate::blockdata::script::{PushBytes, PushBytesBuf, PushBytesErrorReport};

/// The segregated witness program (between 2 and 40 bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessProgram(PushBytesBuf);

#[allow(clippy::len_without_is_empty)] // `is_empty` is always false.
impl WitnessProgram {
    /// Creates a new witness program.
    pub fn new<P>(version: WitnessVersion, program: P) -> Result<Self, Error>
    where
        P: TryInto<PushBytesBuf>,
        <P as TryInto<PushBytesBuf>>::Error: PushBytesErrorReport,
    {
        use Error::*;

        let program = program.try_into().map_err(|error| InvalidLength(error.input_len()))?;
        if program.len() < 2 || program.len() > 40 {
            return Err(InvalidLength(program.len()));
        }

        // Specific segwit v0 check. These addresses can never spend funds sent to them.
        if version == WitnessVersion::V0 && (program.len() != 20 && program.len() != 32) {
            return Err(InvalidSegwitV0Length(program.len()));
        }
        Ok(WitnessProgram(program))
    }

    /// Returns the witness program as a [`PushBytes`] reference.
    pub fn as_push_bytes(&self) -> &PushBytes { &self.0 }

    /// Returns the witness program as a slice reference.
    pub fn as_bytes(&self) -> &[u8] { self.as_push_bytes().as_bytes() }

    /// The length of the witness program.
    pub fn len(&self) -> usize { self.as_bytes().len() }
}

/// Witness program error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0Length(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            InvalidLength(len) =>
                write!(f, "witness program must be between 2 and 40 bytes: length={}", len),
            InvalidSegwitV0Length(len) =>
                write!(f, "a v0 witness program must be either 20 or 32 bytes: length={}", len),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            InvalidLength(_) | InvalidSegwitV0Length(_) => None,
        }
    }
}
