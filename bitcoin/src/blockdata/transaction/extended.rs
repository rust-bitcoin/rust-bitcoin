//! Extended represenatation of transaction.
//!
//! The usual Bitcoin transaction lack data that is required in many scenarios. The most famous is
//! computing transaction fee which is imposible without additional context.
//!
//! To help with these cases this module provides `ExtendedTxIn` and `ExtendedTransaction` which
//! contain extra data.

use alloc::vec::Vec;

use super::{Version, TxIn, TxOut, Txid, Transaction, InputWeightPrediction, IndexOutOfBoundsError, InputsIndexError, OutputsIndexError};
use crate::{absolute, FeeRate, Weight, VarInt, Amount};
use crate::amount::CheckedSum;

/// Transaction input extended with additional data.
///
/// The type parameter allows adding user-defined data which may be useful for signing.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ExtendedTxIn<ExtraData = ()> {
    /// The non-extended transaction input.
    pub txin: TxIn,

    /// The output this input is spending.
    pub previous_output: TxOut,

    /// User-selected data such as key derivation path.
    pub extra: ExtraData,
}

/// Transaction with extended inputs.
///
/// Unlike `[Transaction`] this one has extra data which allows calculating the fee.
/// Note though that this can not store coinbase transactions because their previous inputs don't
/// exist.
#[derive(Clone, Debug)]
pub struct ExtendedTransaction<ExtraTxInData = ()> {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: Version,

    /// List of extended transaction inputs.
    pub inputs: Vec<ExtendedTxIn<ExtraTxInData>>,

    /// List of transaction outputs.
    pub outputs: Vec<TxOut>,

    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    ///
    /// ### Relevant BIPs
    ///
    /// * [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
    /// * [BIP-113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
    pub lock_time: absolute::LockTime,
}

impl<T> ExtendedTransaction<T> {
    /// Converts extended transaction into non-extended transaction.
    ///
    /// This performs one allocation for the vec of inputs.
    pub fn into_transaction(self) -> Transaction {
        Transaction {
            version: self.version,
            input: self.inputs.into_iter().map(|input| input.txin).collect(),
            output: self.outputs,
            lock_time: self.lock_time,
        }
    }

    /// Creates non-extended transaction from extended transaction.
    ///
    /// As opposed to `into_transaction` this allocates for each input and output however, as
    /// unlike `tx.clone().into_transaction()` this avoids cloning the extra input data.
    pub fn to_transaction(&self) -> Transaction {
        Transaction {
            version: self.version,
            input: self.inputs.iter().map(|input| input.txin.clone()).collect(),
            output: self.outputs.clone(),
            lock_time: self.lock_time,
        }
    }

    /// Computes the [`Txid`].
    ///
    /// Hashes the transaction **excluding** the segwit data (i.e. the marker, flag bytes, and the
    /// witness fields themselves). For non-segwit transactions which do not have any segwit data,
    /// this will be equal to [`Transaction::wtxid()`].
    pub fn txid(&self) -> Txid {
        use crate::consensus::Encodable;
        use crate::hashes::Hash;

        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).expect("engines don't error");
        VarInt(self.inputs.len() as u64).consensus_encode(&mut enc).expect("engines don't error");
        for input in &self.inputs {
            input.txin.consensus_encode(&mut enc).expect("engines don't error");
        }
        self.outputs.consensus_encode(&mut enc).expect("engines don't error");
        self.lock_time.consensus_encode(&mut enc).expect("engines don't error");
        Txid::from_engine(enc)
    }

    /// Returns the fee this transaction is paying.
    ///
    /// Returns `None` in case of overflow (creating bitcoins out of thin air).
    pub fn fee(&self) -> Option<Amount> {
        let in_amount = self.inputs.iter().map(|input| input.previous_output.value).checked_sum()?;
        let out_amount = self.outputs.iter().map(|output| output.value).checked_sum()?;
        in_amount.checked_sub(out_amount)
    }

    /// Returns the weight of this transaction, as defined by BIP-141.
    pub fn weight(&self) -> Weight {
        let inputs = self.inputs
            .iter()
            .map(|input| {
                let witness_elements = input.txin.witness.iter().map(|element| element.len());
                InputWeightPrediction::new(input.txin.script_sig.len(), witness_elements)
            });
        let outputs = self.outputs.iter().map(|output| output.script_pubkey.len());
        super::predict_weight(inputs, outputs)
    }

    /// Returns the fee rate of this transaction.
    ///
    /// Returns `None` in case of overflow (creating bitcoins out of thin air).
    pub fn fee_rate(&self) -> Option<FeeRate> {
        // weight is never zero
        Some(self.fee()? / self.weight())
    }

    /// Returns a reference to the input at `input_index` if it exists.
    #[inline]
    pub fn tx_in(&self, input_index: usize) -> Result<&ExtendedTxIn<T>, InputsIndexError> {
        self.inputs
            .get(input_index)
            .ok_or(IndexOutOfBoundsError { index: input_index, length: self.inputs.len() }.into())
    }

    /// Returns a reference to the input at `input_index` if it exists.
    #[inline]
    pub fn tx_in_mut(&mut self, input_index: usize) -> Result<&mut ExtendedTxIn<T>, InputsIndexError> {
        let len = self.inputs.len();
        self.inputs
            .get_mut(input_index)
            .ok_or(IndexOutOfBoundsError { index: input_index, length: len }.into())
    }

    /// Returns a reference to the output at `output_index` if it exists.
    #[inline]
    pub fn tx_out(&self, output_index: usize) -> Result<&TxOut, OutputsIndexError> {
        self.outputs
            .get(output_index)
            .ok_or(IndexOutOfBoundsError { index: output_index, length: self.outputs.len() }.into())
    }

    /// Returns a reference to the output at `output_index` if it exists.
    #[inline]
    pub fn tx_out_mut(&mut self, output_index: usize) -> Result<&mut TxOut, OutputsIndexError> {
        let len = self.inputs.len();
        self.outputs
            .get_mut(output_index)
            .ok_or(IndexOutOfBoundsError { index: output_index, length: len }.into())
    }
}

impl From<ExtendedTransaction> for Transaction {
    fn from(value: ExtendedTransaction) -> Self {
        value.into_transaction()
    }
}
