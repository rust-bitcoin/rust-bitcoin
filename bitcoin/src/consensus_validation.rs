// SPDX-License-Identifier: CC0-1.0

//! Transaction and script validation.
//!
//! Relies on the `bitcoinconsensus` crate that uses Bitcoin Core libconsensus to perform validation.

use core::fmt;

use internals::write_err;

use crate::amount::Amount;
use crate::consensus::encode;
#[cfg(doc)]
use crate::consensus_validation;
use crate::internal_macros::define_extension_trait;
use crate::script::Script;
use crate::transaction::{OutPoint, Transaction, TxOut};

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

/// Verifies that this transaction is able to spend its inputs.
///
/// Shorthand for [`consensus_validation::verify_transaction_with_flags`] with flag
/// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`].
///
/// The `spent` closure should not return the same [`TxOut`] twice!
///
/// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
pub fn verify_transaction<S>(tx: &Transaction, spent: S) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    verify_transaction_with_flags(tx, spent, bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT)
}

/// Verifies that this transaction is able to spend its inputs.
///
/// The `spent` closure should not return the same [`TxOut`] twice!
pub fn verify_transaction_with_flags<S, F>(
    tx: &Transaction,
    mut spent: S,
    flags: F,
) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
    F: Into<u32>,
{
    let serialized_tx = encode::serialize(tx);
    let flags: u32 = flags.into();
    for (idx, input) in tx.input.iter().enumerate() {
        if let Some(output) = spent(&input.previous_output) {
            verify_script_with_flags(
                &output.script_pubkey,
                idx,
                output.value,
                serialized_tx.as_slice(),
                flags,
            )?;
        } else {
            return Err(TxVerifyError::UnknownSpentOutput(input.previous_output));
        }
    }
    Ok(())
}

define_extension_trait! {
    /// Extension functionality to add validation support to the [`Script`] type.
    pub trait ScriptExt impl for Script {
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
        fn verify(
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
        fn verify_with_flags(
            &self,
            index: usize,
            amount: crate::Amount,
            spending_tx: &[u8],
            flags: impl Into<u32>,
        ) -> Result<(), BitcoinconsensusError> {
            verify_script_with_flags(self, index, amount, spending_tx, flags)
        }
    }
}

impl Transaction {
    /// Verifies that this transaction is able to spend its inputs.
    ///
    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`].
    ///
    /// The `spent` closure should not return the same [`TxOut`] twice!
    ///
    /// [`bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT`]: https://docs.rs/bitcoinconsensus/0.106.0+26.0/bitcoinconsensus/constant.VERIFY_ALL_PRE_TAPROOT.html
    pub fn verify<S>(&self, spent: S) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        verify_transaction(self, spent)
    }

    /// Verifies that this transaction is able to spend its inputs.
    ///
    /// The `spent` closure should not return the same [`TxOut`] twice!
    pub fn verify_with_flags<S, F>(&self, spent: S, flags: F) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
        F: Into<u32>,
    {
        verify_transaction_with_flags(self, spent, flags)
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

impl fmt::Display for BitcoinconsensusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "bitcoinconsensus error"; &self.0)
    }
}

#[cfg(all(feature = "std", feature = "bitcoinconsensus"))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// An error during transaction validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxVerifyError {
    /// Error validating the script with bitcoinconsensus library.
    ScriptVerification(BitcoinconsensusError),
    /// Can not find the spent output.
    UnknownSpentOutput(OutPoint),
}

internals::impl_from_infallible!(TxVerifyError);

impl fmt::Display for TxVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TxVerifyError::*;

        match *self {
            ScriptVerification(ref e) => write_err!(f, "bitcoinconsensus verification failed"; e),
            UnknownSpentOutput(ref p) => write!(f, "unknown spent output: {}", p),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TxVerifyError::*;

        match *self {
            ScriptVerification(ref e) => Some(e),
            UnknownSpentOutput(_) => None,
        }
    }
}

impl From<BitcoinconsensusError> for TxVerifyError {
    fn from(e: BitcoinconsensusError) -> Self { TxVerifyError::ScriptVerification(e) }
}
