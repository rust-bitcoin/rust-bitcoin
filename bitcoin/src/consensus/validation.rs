// SPDX-License-Identifier: CC0-1.0

//! Transaction and script validation.
//!
//! Relies on the `bitcoinconsensus` crate that uses Bitcoin Core libconsensus to perform validation.

use core::fmt;

use internals::write_err;

use crate::amount::Amount;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut};
use crate::consensus;

/// Verifies spend of an input script.
///
/// Shorthand for [`consensus::verify_script_with_flags`] with flag
/// [`bitcoinconsensus::VERIFY_ALL`].
///
/// # Parameters
///  * `index` - The input index in spending which is spending this transaction.
///  * `amount` - The amount this script guards.
///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
///
/// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
pub fn verify_script(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), bitcoinconsensus::Error> {
    verify_script_with_flags(script, index, amount, spending_tx, bitcoinconsensus::VERIFY_ALL)
}

/// Verifies spend of an input script.
///
/// # Parameters
///  * `index` - The input index in spending which is spending this transaction.
///  * `amount` - The amount this script guards.
///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL`] and similar.
///
/// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
pub fn verify_script_with_flags<F: Into<u32>>(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
    flags: F,
) -> Result<(), bitcoinconsensus::Error> {
    bitcoinconsensus::verify_with_flags(
        script.as_bytes(),
        amount.to_sat(),
        spending_tx,
        index,
        flags.into(),
    )
}

/// Verifies that this transaction is able to spend its inputs.
///
/// Shorthand for [`consensus::verify_transaction_with_flags`] with flag
/// [`bitcoinconsensus::VERIFY_ALL`].
///
/// The `spent` closure should not return the same [`TxOut`] twice!
///
/// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
pub fn verify_transaction<S>(tx: &Transaction, spent: S) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    verify_transaction_with_flags(tx, spent, bitcoinconsensus::VERIFY_ALL)
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
    let serialized_tx = consensus::serialize(tx);
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

impl Script {
    /// Verifies spend of an input script.
    ///
    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL`].
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///
    /// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
    pub fn verify(
        &self,
        index: usize,
        amount: crate::Amount,
        spending_tx: &[u8],
    ) -> Result<(), bitcoinconsensus::Error> {
        verify_script(self, index, amount, spending_tx)
    }

    /// Verifies spend of an input script.
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL`] and similar.
    ///
    /// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
    pub fn verify_with_flags<F: Into<u32>>(
        &self,
        index: usize,
        amount: crate::Amount,
        spending_tx: &[u8],
        flags: F,
    ) -> Result<(), bitcoinconsensus::Error> {
        verify_script_with_flags(self, index, amount, spending_tx, flags)
    }
}

impl Transaction {
    /// Verifies that this transaction is able to spend its inputs.
    ///
    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL`].
    ///
    /// The `spent` closure should not return the same [`TxOut`] twice!
    ///
    /// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
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

/// An error during transaction validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxVerifyError {
    /// Error validating the script with bitcoinconsensus library.
    ScriptVerification(bitcoinconsensus::Error),
    /// Can not find the spent output.
    UnknownSpentOutput(OutPoint),
}

impl fmt::Display for TxVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TxVerifyError::*;

        match *self {
            ScriptVerification(ref e) => {
                write_err!(f, "bitcoinconsensus verification failed"; bitcoinconsensus_hack::wrap_error(e))
            }
            UnknownSpentOutput(ref p) => write!(f, "unknown spent output: {}", p),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TxVerifyError::*;

        match *self {
            ScriptVerification(ref e) => Some(bitcoinconsensus_hack::wrap_error(e)),
            UnknownSpentOutput(_) => None,
        }
    }
}

impl From<bitcoinconsensus::Error> for TxVerifyError {
    fn from(e: bitcoinconsensus::Error) -> Self { TxVerifyError::ScriptVerification(e) }
}

// If bitcoinonsensus-std is off but bitcoinconsensus is present we patch the error type to
// implement `std::error::Error`.
#[cfg(all(feature = "std", feature = "bitcoinconsensus", not(feature = "bitcoinconsensus-std")))]
mod bitcoinconsensus_hack {
    use core::fmt;

    #[repr(transparent)]
    pub(crate) struct Error(bitcoinconsensus::Error);

    impl fmt::Debug for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(&self.0, f) }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
    }

    // bitcoinconsensus::Error has no sources at this time
    impl std::error::Error for Error {}

    pub(crate) fn wrap_error(error: &bitcoinconsensus::Error) -> &Error {
        // Unfortunately, we cannot have the reference inside `Error` struct because of the 'static
        // bound on `source` return type, so we have to use unsafe to overcome the limitation.
        // SAFETY: the type is repr(transparent) and the lifetimes match
        unsafe { &*(error as *const _ as *const Error) }
    }
}

#[cfg(not(all(
    feature = "std",
    feature = "bitcoinconsensus",
    not(feature = "bitcoinconsensus-std")
)))]
mod bitcoinconsensus_hack {
    #[allow(unused_imports)] // conditionally used
    pub(crate) use core::convert::identity as wrap_error;
}
