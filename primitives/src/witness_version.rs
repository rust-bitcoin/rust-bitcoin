// SPDX-License-Identifier: CC0-1.0

//! The segregated witness version byte as defined by [BIP-0141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP-0016/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP-0141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use units::parse_int;

use crate::opcodes::all::{OP_1, OP_16};
use crate::opcodes::{Opcode, OP_PUSHBYTES_0};

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{ParseWitnessVersionError, InvalidWitnessVersionError};

/// Version of the segregated witness program.
///
/// Helps limit possible versions of the witness according to the specification. If a plain `u8`
/// type was used instead it would mean that the version may be > 16, which would be incorrect.
///
/// First byte of `scriptPubkey` in transaction output for transactions starting with opcodes
/// ranging from 0 to 16 (inclusive).
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "alloc")] {
/// use bitcoin_primitives::witness_version::WitnessVersion;
/// use bitcoin_primitives::ScriptPubKey;
///
/// // A P2WPKH scriptPubKey: OP_0 <20-byte-key-hash>.
/// let script_pubkey = ScriptPubKey::from_bytes(&[
///     0x00, 0x14, 0x8b, 0x9c, 0x1a, 0xcd, 0x2f, 0x2f, 0x1a, 0x4c, 0x5e, 0x3b, 0x7f, 0x91, 0x6d,
///     0x0e, 0x28, 0x3a, 0x54, 0xc7, 0xb2, 0x1d,
/// ]);
///
/// match script_pubkey.witness_version() {
///     Some(WitnessVersion::V0) => println!("segwit v0 output (P2WPKH or P2WSH)"),
///     Some(WitnessVersion::V1) => println!("segwit v1 output (Taproot)"),
///     Some(version) => println!("unknown witness version: {}", version),
///     None => println!("not a witness program"),
/// }
///
/// assert_eq!(script_pubkey.witness_version(), Some(WitnessVersion::V0));
///
/// // Versions are only valid in the range 0 to 16 inclusive.
/// assert_eq!(WitnessVersion::try_from(1_u8), Ok(WitnessVersion::V1));
/// assert!(WitnessVersion::try_from(17_u8).is_err());
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(u8)]
pub enum WitnessVersion {
    /// Initial version of witness program. Used for P2WPKH and P2WSH outputs.
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
    /// version in Bitcoin script. Thus, there is no function to directly convert witness version
    /// into a byte since the conversion requires context (Bitcoin script or just a version number).
    pub fn to_num(self) -> u8 { self as u8 }
}

/// Prints [`WitnessVersion`] number (from 0 to 16) as integer, without any prefix or suffix.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", *self as u8) }
}

impl fmt::LowerHex for WitnessVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.to_num(), f) }
}

impl fmt::UpperHex for WitnessVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.to_num(), f) }
}

impl fmt::Octal for WitnessVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Octal::fmt(&self.to_num(), f) }
}

impl fmt::Binary for WitnessVersion {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Binary::fmt(&self.to_num(), f) }
}

impl FromStr for WitnessVersion {
    type Err = ParseWitnessVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version: u8 =
            parse_int::int_from_str(s).map_err(ParseWitnessVersionError::Unparsable)?;
        Self::try_from(version).map_err(ParseWitnessVersionError::Invalid)
    }
}

impl TryFrom<u8> for WitnessVersion {
    type Error = InvalidWitnessVersionError;

    fn try_from(no: u8) -> Result<Self, Self::Error> {
        Ok(match no {
            0 => Self::V0,
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            6 => Self::V6,
            7 => Self::V7,
            8 => Self::V8,
            9 => Self::V9,
            10 => Self::V10,
            11 => Self::V11,
            12 => Self::V12,
            13 => Self::V13,
            14 => Self::V14,
            15 => Self::V15,
            16 => Self::V16,
            invalid => return Err(InvalidWitnessVersionError { invalid }),
        })
    }
}

impl TryFrom<Opcode> for WitnessVersion {
    type Error = InvalidWitnessVersionError;

    fn try_from(opcode: Opcode) -> Result<Self, Self::Error> {
        match opcode.to_u8() {
            0 => Ok(Self::V0),
            version if version >= OP_1.to_u8() && version <= OP_16.to_u8() =>
                Self::try_from(version - OP_1.to_u8() + 1),
            invalid => Err(InvalidWitnessVersionError { invalid }),
        }
    }
}

impl From<WitnessVersion> for Opcode {
    fn from(version: WitnessVersion) -> Self {
        match version {
            WitnessVersion::V0 => OP_PUSHBYTES_0,
            no => Self::from(OP_1.to_u8() + no.to_num() - 1),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for WitnessVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.to_num())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for WitnessVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        Self::try_from(version).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for WitnessVersion {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let version = u.int_in_range(0..=16)?;
        Ok(Self::try_from(version).expect("range is valid"))
    }
}

/// Error types for the segwit version number.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;
    use units::parse_int::ParseIntError;

    /// Error parsing [`WitnessVersion`] from a string.
    ///
    /// [`WitnessVersion`]: super::WitnessVersion
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ParseWitnessVersionError {
        /// Unable to parse integer from string.
        Unparsable(ParseIntError),
        /// String contained an invalid witness version number.
        Invalid(InvalidWitnessVersionError),
    }

    impl From<Infallible> for ParseWitnessVersionError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for ParseWitnessVersionError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                Self::Unparsable(ref e) => write_err!(f, "integer parse error"; e),
                Self::Invalid(ref e) => write_err!(f, "invalid version number"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParseWitnessVersionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                Self::Unparsable(ref e) => Some(e),
                Self::Invalid(ref e) => Some(e),
            }
        }
    }
    /// Error attempting to create a [`WitnessVersion`] from an integer.
    ///
    /// [`WitnessVersion`]: super::WitnessVersion
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct InvalidWitnessVersionError {
        /// The invalid non-witness version integer.
        pub(super) invalid: u8,
    }

    impl InvalidWitnessVersionError {
        /// Returns the invalid non-witness version integer.
        pub fn invalid_version(&self) -> u8 { self.invalid }
    }

    impl fmt::Display for InvalidWitnessVersionError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "invalid witness script version: {}", self.invalid)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InvalidWitnessVersionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self { invalid: _ } = self;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;

    use super::*;
    use crate::opcodes::OP_PUSHDATA4;

    #[test]
    fn witness_version_to_num() {
        assert_eq!(WitnessVersion::V0.to_num(), 0);
        assert_eq!(WitnessVersion::V1.to_num(), 1);
        assert_eq!(WitnessVersion::V2.to_num(), 2);
        assert_eq!(WitnessVersion::V16.to_num(), 16);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn witness_version_fmt() {
        assert_eq!(format!("{}", WitnessVersion::V0), "0");
        assert_eq!(format!("{}", WitnessVersion::V1), "1");
        assert_eq!(format!("{}", WitnessVersion::V10), "10");
        assert_eq!(format!("{}", WitnessVersion::V16), "16");

        assert_eq!(format!("{:x}", WitnessVersion::V10), "a");
        assert_eq!(format!("{:x}", WitnessVersion::V16), "10");

        assert_eq!(format!("{:X}", WitnessVersion::V10), "A");
        assert_eq!(format!("{:X}", WitnessVersion::V16), "10");

        assert_eq!(format!("{:o}", WitnessVersion::V10), "12");
        assert_eq!(format!("{:o}", WitnessVersion::V16), "20");

        assert_eq!(format!("{:b}", WitnessVersion::V10), "1010");
        assert_eq!(format!("{:b}", WitnessVersion::V16), "10000");
    }

    #[test]
    fn witness_version_try_from_opcode() {
        assert_eq!(WitnessVersion::try_from(OP_PUSHBYTES_0).unwrap(), WitnessVersion::V0);
        assert_eq!(WitnessVersion::try_from(OP_1).unwrap(), WitnessVersion::V1);
        assert_eq!(WitnessVersion::try_from(OP_16).unwrap(), WitnessVersion::V16);

        // Only Opcodes in range OP_1 to OP_16, or 0, are valid.
        let op = Opcode::from(OP_1.to_u8() - 1);
        assert_eq!(WitnessVersion::try_from(op).unwrap_err().invalid_version(), OP_1.to_u8() - 1);
        let op = Opcode::from(0xff);
        assert_eq!(WitnessVersion::try_from(op).unwrap_err().invalid_version(), 0xff);
        assert_eq!(
            WitnessVersion::try_from(Opcode::from(OP_PUSHDATA4)).unwrap_err().invalid_version(),
            OP_PUSHDATA4
        );
    }

    #[test]
    fn witness_version_into_opcode() {
        assert_eq!(Opcode::from(WitnessVersion::V0), OP_PUSHBYTES_0);
        assert_eq!(Opcode::from(WitnessVersion::V1), OP_1);
        assert_eq!(Opcode::from(WitnessVersion::V16), OP_16);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn witness_version_serde_round_trip() {
        for version in 0u8..=16 {
            let wv = WitnessVersion::try_from(version).unwrap();

            let json = serde_json::to_string(&wv).unwrap();
            assert_eq!(json, format!("{}", version));
            assert_eq!(serde_json::from_str::<WitnessVersion>(&json).unwrap(), wv);

            let bin = bincode::serialize(&wv).unwrap();
            assert_eq!(bin, bincode::serialize(&version).unwrap());
            assert_eq!(bincode::deserialize::<WitnessVersion>(&bin).unwrap(), wv);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn witness_version_serde_invalid() {
        assert!(serde_json::from_str::<WitnessVersion>("17").is_err());
        assert!(serde_json::from_str::<WitnessVersion>("255").is_err());
        assert!(serde_json::from_str::<WitnessVersion>("-1").is_err());
    }

    #[test]
    fn witness_version_opcode_round_trip() {
        for version in 0u8..=16 {
            let wv = WitnessVersion::try_from(version).unwrap();
            let opcode = Opcode::from(wv);
            assert_eq!(WitnessVersion::try_from(opcode).unwrap(), wv);
        }
    }
}
