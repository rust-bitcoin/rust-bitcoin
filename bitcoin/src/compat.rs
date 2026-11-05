// SPDX-License-Identifier: CC0-1.0

//! Stable compatibility layer.
//!
//! This module re-exports types from the units and primitives crates. The aim is to ease
//! the upgrade path from `bitcoin 0.32` to subsequent `bitcoin` versions as we release them.
//!
//! With this module, coupled with the `to_stable`/`from_stable` functions, downstream projects can
//! update to use stable crates at their leisure without the whole ecosystem having to upgrade at
//! once. The intention is to provide stable types for the most common `rust-bitcoin` types used by
//! downstream libraries.
//!
//! # Examples
//!
//! ```
//! use bitcoin::Sequence;
//!
//! let seq = Sequence::default();
//! let stable = seq.to_stable();
//!
//! // Now call into some other library that uses stable types in its API.
//! // E.g., `other_lib::some_function(stable);`
//! let unstable = Sequence::from_stable(stable);
//! assert_eq!(unstable, seq);
//! ```
//!
//! Scripts in the primitives crate are tagged by their role. Specify the tag when converting
//! an untyped script; converting back discards the tag without changing the bytes.
//!
//! ```
//! use bitcoin::{compat, ScriptBuf};
//!
//! let script = ScriptBuf::from_bytes(vec![0x51]);
//! let stable: compat::ScriptPubKeyBuf = script.clone().to_stable();
//! assert_eq!(ScriptBuf::from_stable(stable), script);
//! ```
//!
//! Outputs, transactions, and blocks can contain amounts above the stable limit. Their conversions
//! return an [`AmountConversionError`] containing the original value and the location of the
//! invalid amount. The underlying units error is available through
//! [`AmountConversionError::out_of_range_error`].
//! Transaction and block conversions check every amount before consuming the original, so script
//! buffers are moved rather than copied on success.
//!
//! ```
//! use bitcoin::{Amount, TxOut};
//!
//! let output = TxOut::NULL;
//! let error = output.to_stable().unwrap_err();
//! assert_eq!(error.location(), None);
//! let mut output = error.into_input();
//! output.value = Amount::from_sat(1_000);
//! let stable = output.to_stable().unwrap();
//! assert_eq!(stable.amount.to_sat(), 1_000);
//! ```

use core::convert::Infallible;
use core::fmt;

use crate::internal_macros::write_err;

#[doc(inline)]
#[rustfmt::skip]
pub use bitcoin_primitives_stable::{
    block, merkle_tree, opcodes, script, transaction, witness, witness_version,
    Block, BlockChecked, BlockHash, BlockHeader, BlockUnchecked, BlockValidation, BlockVersion,
    OutPoint, RedeemScript, RedeemScriptBuf, ScriptCode, ScriptPubKey, ScriptPubKeyBuf,
    ScriptSig, ScriptSigBuf, SignetBlockScript, SignetBlockScriptBuf, TapScript, TapScriptBuf,
    Transaction, TransactionVersion, TxIn, TxOut, Txid, Witness, WitnessCommitment, WitnessScript,
    WitnessScriptBuf, Wtxid,
};
#[doc(inline)]
pub use bitcoin_primitives_stable::{
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    opcodes::Opcode,
    transaction::Ntxid,
    witness_version::WitnessVersion,
};
#[doc(inline)]
pub use bitcoin_units_stable::{
    amount, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
};
#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    locktime::{absolute, relative},
    pow::{CompactTarget, Target, Work},
    result::NumOpResult,
    sequence::Sequence,
    time::BlockTime,
    weight::Weight
};

/// The location of an amount that prevented a conversion.
///
/// Output indices are zero-based. A standalone output conversion has no location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmountConversionLocation {
    /// An output in a transaction.
    TransactionOutput {
        /// Zero-based index of the output in the transaction.
        output_index: usize,
    },
    /// An output in a transaction in a block.
    BlockTransactionOutput {
        /// Zero-based index of the transaction in the block.
        transaction_index: usize,
        /// Zero-based index of the output in the transaction.
        output_index: usize,
    },
}

/// An amount outside the stable range prevented a conversion.
///
/// The original value is preserved unchanged and can be recovered with [`Self::into_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AmountConversionError<T> {
    // Boxed so that `Result<_, AmountConversionError<Block>>` stays small.
    input: alloc::boxed::Box<T>,
    location: Option<AmountConversionLocation>,
    error: amount::OutOfRangeError,
}

impl<T> AmountConversionError<T> {
    pub(crate) fn new(
        input: T,
        location: Option<AmountConversionLocation>,
        error: amount::OutOfRangeError,
    ) -> Self {
        Self { input: alloc::boxed::Box::new(input), location, error }
    }

    /// Returns the original value.
    pub fn input(&self) -> &T { &self.input }

    /// Returns the location of the invalid amount, if this conversion has an output index.
    pub fn location(&self) -> Option<AmountConversionLocation> { self.location }

    /// Returns the units error for the invalid amount.
    pub fn out_of_range_error(&self) -> &amount::OutOfRangeError { &self.error }

    /// Recovers the original value.
    pub fn into_input(self) -> T { *self.input }
}

impl<T> From<Infallible> for AmountConversionError<T> {
    fn from(never: Infallible) -> Self { match never {} }
}

impl<T> fmt::Display for AmountConversionError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.location() {
            None => write_err!(f, "cannot convert to stable type"; self.error),
            Some(AmountConversionLocation::TransactionOutput { output_index }) => {
                write_err!(f, "cannot convert transaction output at index {}", output_index; self.error)
            }
            Some(AmountConversionLocation::BlockTransactionOutput {
                transaction_index,
                output_index,
            }) => {
                write_err!(
                    f,
                    "cannot convert block transaction output at transaction index {} and output index {}",
                    transaction_index,
                    output_index;
                    self.error
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl<T: fmt::Debug> std::error::Error for AmountConversionError<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}
