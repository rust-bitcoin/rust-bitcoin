// SPDX-License-Identifier: CC0-1.0

//! Script validation.
//!
//! Relies on the `bitcoinconsensus` crate that uses Bitcoin Core libconsensus to perform validation.

use core::fmt;

use internals::write_err;

#[cfg(doc)]
use crate::consensus_validation;
use crate::{Amount, Script};

/// Verifies spend of an input script.
///
/// Shorthand for [`consensus_validation::verify_script_with_flags`] with flag
/// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`].
///
/// # Parameters
///
///  * `index` - The input index in spending which is spending this transaction.
///  * `amount` - The amount this script guards.
///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
///
/// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
pub fn verify_script(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), BitcoinconsensusError> {
    verify_script_with_flags(
        script,
        index,
        amount,
        spending_tx,
        bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT,
    )
}

/// Verifies spend of an input script.
///
/// # Parameters
///
///  * `index` - The input index in spending which is spending this transaction.
///  * `amount` - The amount this script guards.
///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`] and similar.
///
/// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
pub fn verify_script_with_flags<F: Into<u32>>(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
    flags: F,
) -> Result<(), BitcoinconsensusError> {
    bitcoinconsensus::verify_with_flags(
        script.as_bytes(),
        amount.to_sat(),
        spending_tx,
        None,
        index,
        flags.into(),
    )
    .map_err(BitcoinconsensusError)
}

impl Script {
    /// Verifies spend of an input script.
    ///
    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`].
    ///
    /// # Parameters
    ///
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///
    /// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
    pub fn verify(
        &self,
        index: usize,
        amount: crate::Amount,
        spending_tx: &[u8],
    ) -> Result<(), BitcoinconsensusError> {
        verify_script(self, index, amount, spending_tx)
    }

    /// Verifies spend of an input script.
    ///
    /// # Parameters
    ///
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`] and similar.
    ///
    /// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
    pub fn verify_with_flags<F: Into<u32>>(
        &self,
        index: usize,
        amount: crate::Amount,
        spending_tx: &[u8],
        flags: F,
    ) -> Result<(), BitcoinconsensusError> {
        verify_script_with_flags(self, index, amount, spending_tx, flags)
    }
}

/// Wrapped error from `bitcoinconsensus`.
// We do this for two reasons:
// 1. We don't want the error to be part of the public API because we do not want to expose the
//    unusual versioning used in `bitcoinconsensus` to users of `rust-bitcoin`.
// 2. We want to implement `std::error::Error` if the "std" feature is enabled in `rust-bitcoin` but
//    not in `bitcoinconsensus`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BitcoinconsensusError(bitcoinconsensus::Error);

// Remove this when transaction validation moves to this module.
// https://github.com/rust-bitcoin/rust-bitcoin/issues/3060
impl From<bitcoinconsensus::Error> for BitcoinconsensusError {
    fn from(e: bitcoinconsensus::Error) -> Self { Self(e) }
}

impl fmt::Display for BitcoinconsensusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "bitcoinconsensus error"; &self.0)
    }
}

#[cfg(all(feature = "std", feature = "bitcoinconsensus-std"))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(all(feature = "std", not(feature = "bitcoinconsensus-std")))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
