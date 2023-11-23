//! The segregated witness version byte as defined by [BIP141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::fmt;
use core::str::FromStr;

use bech32::Fe32;
use internals::write_err;

use crate::blockdata::opcodes::all::*;
use crate::blockdata::opcodes::Opcode;
use crate::blockdata::script::Instruction;
use crate::error::ParseIntError;

/// Version of the segregated witness program.
///
/// Helps limit possible versions of the witness according to the specification. If a plain `u8`
/// type was used instead it would mean that the version may be > 16, which would be incorrect.
///
/// First byte of `scriptPubkey` in transaction output for transactions starting with opcodes
/// ranging from 0 to 16 (inclusive).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum WitnessVersion {
    /// Initial version of witness program. Used for P2WPKH and P2WPK outputs
    V0 = 0,
    /// Version of witness program used for Taproot P2TR outputs.
    V1 = 1,
    /// Future (unsupported) version of witness program.
    V2 = 2,
    /// Future (unsupported) version of witness program.
    V3 = 3,
    /// Future (unsupported) version of witness program.
    V4 = 4,
    /// Future (unsupported) version of witness program.
    V5 = 5,
    /// Future (unsupported) version of witness program.
    V6 = 6,
    /// Future (unsupported) version of witness program.
    V7 = 7,
    /// Future (unsupported) version of witness program.
    V8 = 8,
    /// Future (unsupported) version of witness program.
    V9 = 9,
    /// Future (unsupported) version of witness program.
    V10 = 10,
    /// Future (unsupported) version of witness program.
    V11 = 11,
    /// Future (unsupported) version of witness program.
    V12 = 12,
    /// Future (unsupported) version of witness program.
    V13 = 13,
    /// Future (unsupported) version of witness program.
    V14 = 14,
    /// Future (unsupported) version of witness program.
    V15 = 15,
    /// Future (unsupported) version of witness program.
    V16 = 16,
}

impl WitnessVersion {
    /// Returns integer version number representation for a given [`WitnessVersion`] value.
    ///
    /// NB: this is not the same as an integer representation of the opcode signifying witness
    /// version in bitcoin script. Thus, there is no function to directly convert witness version
    /// into a byte since the conversion requires context (bitcoin script or just a version number).
    pub fn to_num(self) -> u8 { self as u8 }

    /// Converts this witness version to a GF32 field element.
    pub fn to_fe(self) -> Fe32 {
        Fe32::try_from(self.to_num()).expect("0-16 are valid fe32 values")
    }
}

/// Prints [`WitnessVersion`] number (from 0 to 16) as integer, without any prefix or suffix.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", *self as u8) }
}

impl FromStr for WitnessVersion {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version: u8 = crate::parse::int(s).map_err(FromStrError::Unparsable)?;
        Ok(WitnessVersion::try_from(version)?)
    }
}

impl TryFrom<bech32::Fe32> for WitnessVersion {
    type Error = TryFromError;

    fn try_from(value: Fe32) -> Result<Self, Self::Error> { Self::try_from(value.to_u8()) }
}

impl TryFrom<u8> for WitnessVersion {
    type Error = TryFromError;

    fn try_from(no: u8) -> Result<Self, Self::Error> {
        use WitnessVersion::*;

        Ok(match no {
            0 => V0,
            1 => V1,
            2 => V2,
            3 => V3,
            4 => V4,
            5 => V5,
            6 => V6,
            7 => V7,
            8 => V8,
            9 => V9,
            10 => V10,
            11 => V11,
            12 => V12,
            13 => V13,
            14 => V14,
            15 => V15,
            16 => V16,
            invalid => return Err(TryFromError { invalid }),
        })
    }
}

impl TryFrom<Opcode> for WitnessVersion {
    type Error = TryFromError;

    fn try_from(opcode: Opcode) -> Result<Self, Self::Error> {
        match opcode.to_u8() {
            0 => Ok(WitnessVersion::V0),
            version if version >= OP_PUSHNUM_1.to_u8() && version <= OP_PUSHNUM_16.to_u8() =>
                WitnessVersion::try_from(version - OP_PUSHNUM_1.to_u8() + 1),
            invalid => Err(TryFromError { invalid }),
        }
    }
}

impl<'a> TryFrom<Instruction<'a>> for WitnessVersion {
    type Error = TryFromInstructionError;

    fn try_from(instruction: Instruction) -> Result<Self, Self::Error> {
        match instruction {
            Instruction::Op(op) => Ok(WitnessVersion::try_from(op)?),
            Instruction::PushBytes(bytes) if bytes.is_empty() => Ok(WitnessVersion::V0),
            Instruction::PushBytes(_) => Err(TryFromInstructionError::DataPush),
        }
    }
}

impl From<WitnessVersion> for Fe32 {
    fn from(version: WitnessVersion) -> Self { version.to_fe() }
}

impl From<WitnessVersion> for Opcode {
    fn from(version: WitnessVersion) -> Opcode {
        match version {
            WitnessVersion::V0 => OP_PUSHBYTES_0,
            no => Opcode::from(OP_PUSHNUM_1.to_u8() + no.to_num() - 1),
        }
    }
}

/// Error parsing [`WitnessVersion`] from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromStrError {
    /// Unable to parse integer from string.
    Unparsable(ParseIntError),
    /// String contained an invalid witness version number.
    Invalid(TryFromError),
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromStrError::*;

        match *self {
            Unparsable(ref e) => write_err!(f, "integer parse error"; e),
            Invalid(ref e) => write_err!(f, "invalid version number"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromStrError::*;

        match *self {
            Unparsable(ref e) => Some(e),
            Invalid(ref e) => Some(e),
        }
    }
}

impl From<TryFromError> for FromStrError {
    fn from(e: TryFromError) -> Self { Self::Invalid(e) }
}

/// Error attempting to create a [`WitnessVersion`] from an [`Instruction`]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TryFromInstructionError {
    /// Cannot not convert OP to a witness version.
    TryFrom(TryFromError),
    /// Cannot create a witness version from non-zero data push.
    DataPush,
}

impl fmt::Display for TryFromInstructionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TryFromInstructionError::*;

        match *self {
            TryFrom(ref e) => write_err!(f, "opcode is not a valid witness version"; e),
            DataPush => write!(f, "non-zero data push opcode is not a valid witness version"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TryFromInstructionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TryFromInstructionError::*;

        match *self {
            TryFrom(ref e) => Some(e),
            DataPush => None,
        }
    }
}

impl From<TryFromError> for TryFromInstructionError {
    fn from(e: TryFromError) -> Self { Self::TryFrom(e) }
}

/// Error attempting to create a [`WitnessVersion`] from an integer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TryFromError {
    /// The invalid non-witness version integer.
    pub invalid: u8,
}

impl fmt::Display for TryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid witness script version: {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TryFromError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
