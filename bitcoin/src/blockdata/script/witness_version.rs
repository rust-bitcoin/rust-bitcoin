//! The segregated witness version byte as defined by [BIP-0141].
//!
//! > A scriptPubKey (or redeemScript as defined in BIP-0016/P2SH) that consists of a 1-byte push
//! > opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new special
//! > meaning. The value of the first push is called the "version byte". The following byte
//! > vector pushed is called the "witness program".
//!
//! [BIP-0141]: <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>

use crate::script::Instruction;

#[rustfmt::skip]            // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{ParseWitnessVersionError, TryFromInstructionError, InvalidWitnessVersionError};

#[doc(inline)]
pub use primitives::witness_version::WitnessVersion;

impl TryFrom<Instruction<'_>> for WitnessVersion {
    type Error = TryFromInstructionError;

    fn try_from(instruction: Instruction) -> Result<Self, Self::Error> {
        match instruction {
            Instruction::Op(op) => Ok(Self::try_from(op)?),
            Instruction::PushBytes(bytes) if bytes.is_empty() => Ok(Self::V0),
            Instruction::PushBytes(_) => Err(TryFromInstructionError::DataPush),
        }
    }
}

/// Error types for the segwit version number.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(no_inline)]
    pub use primitives::witness_version::error::{ParseWitnessVersionError, InvalidWitnessVersionError};

    /// Error attempting to create a [`WitnessVersion`] from an [`Instruction`]
    ///
    /// [`WitnessVersion`]: super::WitnessVersion
    /// [`Instruction`]: super::Instruction
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TryFromInstructionError {
        /// Cannot convert OP to a witness version.
        TryFrom(InvalidWitnessVersionError),
        /// Cannot create a witness version from non-zero data push.
        DataPush,
    }

    impl From<Infallible> for TryFromInstructionError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for TryFromInstructionError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::TryFrom(ref e) => write_err!(f, "opcode is not a valid witness version"; e),
                Self::DataPush =>
                    write!(f, "non-zero data push opcode is not a valid witness version"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for TryFromInstructionError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::TryFrom(ref e) => Some(e),
                Self::DataPush => None,
            }
        }
    }

    impl From<InvalidWitnessVersionError> for TryFromInstructionError {
        fn from(e: InvalidWitnessVersionError) -> Self { Self::TryFrom(e) }
    }
}
