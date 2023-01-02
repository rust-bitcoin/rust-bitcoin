use core::borrow::Borrow;
use core::convert::Infallible;
use crate::{Transaction, TxOut, OutPoint};

/// Provides control over verifying the transaction.
///
/// This can be used to perform complete or partial verification of the transaction.
/// Partial verification is useful in various contracts to check that particular inputs are valid
/// without knowing signatures of other inputs.
#[must_use = "Creating TransactionVerifier doesn't verify the transaction, call methods on it"]
pub struct TransactionVerifier<'a> {
    transaction: &'a Transaction,
    /// Serialized transaction as a cache.
    bytes: Vec<u8>,
}

impl<'a> TransactionVerifier<'a> {
    /// Creates the verifier from a transaction.
    ///
    /// Note that this function pre-allocates cache. Avoid repeatedly calling it with the same
    /// transaction if possible.
    pub fn from_transaction(transaction: &'a Transaction) -> Self {
        let bytes = super::encode::serialize(&transaction);

        TransactionVerifier {
            transaction,
            bytes,
        }
    }

    /// Verifies a specific input.
    pub fn verify_single_input(&self, index: usize, prev_out: &TxOut) -> Result<(), Error<Infallible>> {
        self.verify_single_input_with_flags(index, prev_out, bitcoinconsensus::VERIFY_ALL)
    }

    /// Verifies a specific input using custom flags.
    pub fn verify_single_input_with_flags(&self, index: usize, prev_out: &TxOut, flags: u32) -> Result<(), Error<Infallible>> {
        let value = crate::Amount::from_sat(prev_out.value);
        prev_out.script_pubkey.verify_with_flags(index, value, &self.bytes, flags)
            .map_err(VerificationError)
            .map_err(Error::Verification)
    }

    /// Verifies all inputs using prepared previous outputs.
    ///
    /// This is useful if you have previous outputs already prepared in some collection in the
    /// order they appear in the inputs.
    ///
    /// If the number of previous outputs doesn't match the number of inputs the function fails.
    pub fn verify_inputs_sequential<I>(&self, prev_outs: I) -> Result<(), Error<InputCountMismatch>>
        where I: IntoIterator, I::Item: Borrow<TxOut>
    {
        self.verify_inputs_sequential_with_flags(prev_outs, bitcoinconsensus::VERIFY_ALL)
    }

    /// Verifies all inputs using prepared previous outputs and custom flags.
    ///
    /// This is useful if you have previous outputs already prepared in some collection in the
    /// order they appear in the inputs.
    ///
    /// If the number of previous outputs doesn't match the number of inputs the function fails.
    pub fn verify_inputs_sequential_with_flags<I>(&self, prev_outs: I, flags: u32) -> Result<(), Error<InputCountMismatch>>
        where I: IntoIterator, I::Item: Borrow<TxOut>
    {
        let mut count = 0;
        let mut iter = prev_outs.into_iter().fuse();
        // prevent iteratig past the number of inputs which is already an error
        for prev_out in iter.by_ref().take(self.transaction.input.len()) {
            self.verify_single_input_with_flags(count, prev_out.borrow(), flags)?;
            // can't overfow because of the limit above
            count += 1;
        }
        if count == self.transaction.input.len() {
            if iter.next().is_none() {
                Ok(())
            } else {
                Err(Error::Input(InputCountMismatch { expected: self.transaction.input.len(), got: None }))
            }
        } else {
            Err(Error::Input(InputCountMismatch { expected: self.transaction.input.len(), got: Some(count) }))
        }
    }

    /// Verifies all inputs fetching each previous output by the out point.
    ///
    /// For each input this calls `get_prev_out` which is supposed to return the appropriate
    /// output. You can return any custom error in case of failure. Most commonly this will be not
    /// found error, so there is [`MissingUtxo`] type prepared for you. However if the inputs are
    /// not in memory but e.g. in a database you may return some kind of IO Error as well.
    pub fn verify_inputs_by_out_point<E, F>(&self, get_prev_out: F) -> Result<(), Error<E>> 
        where F: FnMut(&OutPoint) -> Result<TxOut, E>
    {
        self.verify_inputs_by_out_point_with_flags(bitcoinconsensus::VERIFY_ALL, get_prev_out)
    }

    /// Verifies all inputs using custom flags, fetching each previous output by the out point.
    ///
    /// For each input this calls `get_prev_out` which is supposed to return the appropriate
    /// output. You can return any custom error in case of failure. Most commonly this will be not
    /// found error, so there is [`MissingUtxo`] type prepared for you. However if the inputs are
    /// not in memory but e.g. in a database you may return some kind of IO Error as well.
    pub fn verify_inputs_by_out_point_with_flags<O, E, GetPrevOut>(&self, flags: u32, mut get_prev_out: GetPrevOut) -> Result<(), Error<E>> 
        where
            GetPrevOut: FnMut(&OutPoint) -> Result<O, E>,
            O: Borrow<TxOut>
    {
        for (idx, input) in self.transaction.input.iter().enumerate() {
            let output = get_prev_out(&input.previous_output).map_err(Error::Input)?;
            self.verify_single_input_with_flags(idx, output.borrow(), flags)
                .map_err(Error::infallible_into)?;
        }
        Ok(())
    }
}

/// Verification error.
pub enum Error<InputError> {
    /// Verification of the transaction failed.
    Verification(VerificationError),
    /// The previous output(s) is (are) unavailable or invalid.
    Input(InputError),
}

impl Error<Infallible> {
    /// Converts an error with infallible input into arbitrary error.
    fn infallible_into<E2>(self) -> Error<E2> {
        match self {
            Error::Verification(error) => Error::Verification(error),
            Error::Input(never) => match never {},
        }
    }
}

/// Error returned when verification fails.
pub struct VerificationError(crate::blockdata::script::Error);

macro_rules! impl_from_infallible {
    ($type:ty) => {
        impl From<Error<Infallible>> for Error<$type> {
            fn from(error: Error<Infallible>) -> Self {
                error.infallible_into()
            }
        }
    }
}

impl_from_infallible!(InputCountMismatch);
impl_from_infallible!(MissingUtxo);

/// The number of previous outputs doesn't match the number of inputs.
#[derive(Debug)]
pub struct InputCountMismatch {
    expected: usize,
    /// `None` means "too many", potentially infinite
    got: Option<usize>,
}

/// A UTXO is missing.
#[derive(Debug)]
pub struct MissingUtxo {
    out_point: OutPoint,
}

impl MissingUtxo {
    /// Creates the error instance.
    pub fn new(out_point: OutPoint) -> Self {
        MissingUtxo {
            out_point,
        }
    }
}
