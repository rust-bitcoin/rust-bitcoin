//! The segregated witness version byte as defined by [BIP141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;

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

    /// Determines the checksum variant. See BIP-0350 for specification.
    pub fn bech32_variant(&self) -> bech32::Variant {
        match self {
            WitnessVersion::V0 => bech32::Variant::Bech32,
            _ => bech32::Variant::Bech32m,
        }
    }
}

/// Prints [`WitnessVersion`] number (from 0 to 16) as integer, without any prefix or suffix.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", *self as u8) }
}

impl FromStr for WitnessVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version: u8 = crate::parse::int(s).map_err(Error::Unparsable)?;
        WitnessVersion::try_from(version)
    }
}

impl TryFrom<bech32::u5> for WitnessVersion {
    type Error = Error;

    /// Converts 5-bit unsigned integer value matching single symbol from Bech32(m) address encoding
    /// ([`bech32::u5`]) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    ///
    /// Version of the Witness program.
    ///
    /// # Errors
    ///
    /// If the integer does not correspond to any witness version, errors with [`Error::Invalid`].
    fn try_from(value: bech32::u5) -> Result<Self, Self::Error> { Self::try_from(value.to_u8()) }
}

impl TryFrom<u8> for WitnessVersion {
    type Error = Error;

    /// Converts an 8-bit unsigned integer value into [`WitnessVersion`] variant.
    ///
    /// # Returns
    ///
    /// Version of the Witness program.
    ///
    /// # Errors
    ///
    /// If the integer does not correspond to any witness version, errors with [`Error::Invalid`].
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
            wrong => return Err(Error::Invalid(wrong)),
        })
    }
}

impl TryFrom<Opcode> for WitnessVersion {
    type Error = Error;

    /// Converts bitcoin script opcode into [`WitnessVersion`] variant.
    ///
    /// # Returns
    ///
    /// Version of the Witness program (for opcodes in range of `OP_0`..`OP_16`).
    ///
    /// # Errors
    ///
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::Malformed`].
    fn try_from(opcode: Opcode) -> Result<Self, Self::Error> {
        match opcode.to_u8() {
            0 => Ok(WitnessVersion::V0),
            version if version >= OP_PUSHNUM_1.to_u8() && version <= OP_PUSHNUM_16.to_u8() =>
                WitnessVersion::try_from(version - OP_PUSHNUM_1.to_u8() + 1),
            _ => Err(Error::Malformed),
        }
    }
}

impl<'a> TryFrom<Instruction<'a>> for WitnessVersion {
    type Error = Error;

    /// Converts bitcoin script [`Instruction`] (parsed opcode) into [`WitnessVersion`] variant.
    ///
    /// # Returns
    ///
    /// Version of the Witness program for [`Instruction::Op`] and [`Instruction::PushBytes`] with
    /// byte value within `1..=16` range.
    ///
    /// # Errors
    ///
    /// If the opcode does not correspond to any witness version, errors with
    /// [`Error::Malformed`] for the rest of opcodes.
    fn try_from(instruction: Instruction) -> Result<Self, Self::Error> {
        match instruction {
            Instruction::Op(op) => WitnessVersion::try_from(op),
            Instruction::PushBytes(bytes) if bytes.is_empty() => Ok(WitnessVersion::V0),
            Instruction::PushBytes(_) => Err(Error::Malformed),
        }
    }
}

impl From<WitnessVersion> for bech32::u5 {
    /// Converts [`WitnessVersion`] instance into corresponding Bech32(m) u5-value ([`bech32::u5`]).
    fn from(version: WitnessVersion) -> Self {
        bech32::u5::try_from_u8(version.to_num()).expect("WitnessVersion must be 0..=16")
    }
}

impl From<WitnessVersion> for Opcode {
    /// Converts [`WitnessVersion`] instance into corresponding Bitcoin scriptopcode (`OP_0`..`OP_16`).
    fn from(version: WitnessVersion) -> Opcode {
        match version {
            WitnessVersion::V0 => OP_PUSHBYTES_0,
            no => Opcode::from(OP_PUSHNUM_1.to_u8() + no.to_num() - 1),
        }
    }
}

/// Witness version error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Bech32 u5 conversion error.
    Bech32(bech32::Error),
    /// Script version must be 0 to 16 inclusive.
    Invalid(u8),
    /// Unable to parse witness version from string.
    Unparsable(ParseIntError),
    /// Bitcoin script opcode does not match any known witness version, the script is malformed.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Bech32(ref e) => write_err!(f, "bech32 u5 conversion error"; e),
            Invalid(v) => write!(f, "invalid witness script version: {}", v),
            Unparsable(ref e) => write_err!(f, "incorrect format of a witness version byte"; e),
            Malformed => f.write_str("bitcoin script opcode does not match any known witness version, the script is malformed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            Bech32(ref e) => Some(e),
            Unparsable(ref e) => Some(e),
            Invalid { .. } | Malformed => None,
        }
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error { Error::Bech32(e) }
}
