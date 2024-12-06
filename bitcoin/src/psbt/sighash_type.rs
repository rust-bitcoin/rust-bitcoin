// SPDX-License-Identifier: CC0-1.0

//! The PSBT sighash type.

use core::fmt;
use core::str::FromStr;

use crate::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, NonStandardSighashTypeError, SighashTypeParseError,
    TapSighashType,
};

/// A Signature hash type for the corresponding input.
///
/// As of Taproot upgrade, the signature hash type can be either [`EcdsaSighashType`] or
/// [`TapSighashType`] but it is not possible to know directly which signature hash type the user is
/// dealing with. Therefore, the user is responsible for converting to/from [`PsbtSighashType`]
/// from/to the desired signature hash type they need.
///
/// # Examples
///
/// ```
/// use bitcoin::{EcdsaSighashType, TapSighashType};
/// use bitcoin::psbt::PsbtSighashType;
///
/// let _ecdsa_sighash_all: PsbtSighashType = EcdsaSighashType::All.into();
/// let _tap_sighash_all: PsbtSighashType = TapSighashType::All.into();
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PsbtSighashType {
    pub(in crate::psbt) inner: u32,
}

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.taproot_hash_ty() {
            Err(_) => write!(f, "{:#x}", self.inner),
            Ok(taproot_hash_ty) => fmt::Display::fmt(&taproot_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        //
        // NB: some of Taproot sighash types are non-standard for pre-Taproot
        // inputs. We also do not support SIGHASH_RESERVED in verbatim form
        // ("0xFF" string should be used instead).
        if let Ok(ty) = s.parse::<TapSighashType>() {
            return Ok(ty.into());
        }

        // We accept non-standard sighash values.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(PsbtSighashType { inner });
        }

        Err(SighashTypeParseError { unrecognized: s.to_owned() })
    }
}
impl From<EcdsaSighashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSighashType) -> Self {
        PsbtSighashType { inner: ecdsa_hash_ty as u32 }
    }
}

impl From<TapSighashType> for PsbtSighashType {
    fn from(taproot_hash_ty: TapSighashType) -> Self {
        PsbtSighashType { inner: taproot_hash_ty as u32 }
    }
}

impl PsbtSighashType {
    /// Ambiguous `ALL` sighash type, may refer to either [`EcdsaSighashType::All`]
    /// or [`TapSighashType::All`].
    ///
    /// This is equivalent to either `EcdsaSighashType::All.into()` or `TapSighashType::All.into()`.
    /// For sighash types other than `ALL` use the ECDSA or Taproot sighash type directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::{EcdsaSighashType, TapSighashType};
    /// use bitcoin::psbt::PsbtSighashType;
    /// let _ecdsa_sighash_anyone_can_pay: PsbtSighashType = EcdsaSighashType::AllPlusAnyoneCanPay.into();
    /// let _tap_sighash_anyone_can_pay: PsbtSighashType = TapSighashType::AllPlusAnyoneCanPay.into();
    /// ```
    pub const ALL: PsbtSighashType = PsbtSighashType { inner: 0x01 };

    /// Returns the [`EcdsaSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        EcdsaSighashType::from_standard(self.inner)
    }

    /// Returns the [`TapSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn taproot_hash_ty(self) -> Result<TapSighashType, InvalidSighashTypeError> {
        if self.inner > 0xffu32 {
            Err(InvalidSighashTypeError(self.inner))
        } else {
            TapSighashType::from_consensus_u8(self.inner as u8)
        }
    }

    /// Constructs a new [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag
    /// ([`EcdsaSighashType`], [`TapSighashType`] respectively).
    pub fn from_u32(n: u32) -> PsbtSighashType { PsbtSighashType { inner: n } }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 { self.inner }
}
