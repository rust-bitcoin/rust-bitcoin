// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use super::serialize::{self, Deserialize, Serialize};
use crate::consensus::encode;
use crate::prelude::Vec;

/// The PSBT version.
///
/// Maintains an invariant that only version 0 and 2 can exist.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Version {
    /// The original PSBT format [BIP-174].
    ///
    /// [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
    Zero,
    /// The second PSBT version [BIP-370].
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
    Two,
}

impl Version {
    /// Returns the version number as a `u32`.
    pub fn to_u32(self) -> u32 {
        match self {
            Version::Zero => 0,
            Version::Two => 2,
        }
    }
}

impl From<Version> for u32 {
    fn from(v: Version) -> u32 { v.to_u32() }
}

impl TryFrom<u32> for Version {
    type Error = UnsupportedVersionError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Version::Zero),
            2 => Ok(Version::Two),
            n => Err(UnsupportedVersionError(n)),
        }
    }
}

impl Serialize for Version {
    fn serialize(&self) -> Vec<u8> { encode::serialize(&self.to_u32()) }
}

impl Deserialize for Version {
    fn deserialize(bytes: &[u8]) -> Result<Self, serialize::Error> {
        let n: u32 = encode::deserialize(bytes)?;
        let version = Version::try_from(n)?;
        Ok(version)
    }
}

/// Unsupported PSBT version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedVersionError(u32);

impl fmt::Display for UnsupportedVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported version, we only support v0 and v2: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
