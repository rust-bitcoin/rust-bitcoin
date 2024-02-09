// SPDX-License-Identifier: CC0-1.0

//! Transaction and script validation.
//!
//! Relies on the `bitcoinconsensus` crate that uses Bitcoin Core libconsensus to perform validation.

use core::fmt;

use internals::write_err;

use crate::amount::Amount;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut};
#[cfg(doc)]
use crate::consensus;
use crate::consensus::encode;

/// Verifies spend of a pre-taproot input script.
pub fn verify_pre_taproot_script(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), BitcoinconsensusError> {
    bitcoinconsensus::verify(script.as_bytes(), amount.to_sat(), spending_tx, None, index).map_err(BitcoinconsensusError)
}

/// Verifies spend of a taproot input script.
pub fn verify_taproot_script(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
    spent_outputs: &[TxOut],
) -> Result<(), BitcoinconsensusError> {
    use bitcoinconsensus::Utxo;

    // We need this to have somewhere in memory to reference - is this correct?
    let script_pubkeys = spent_outputs.iter().map(|tx_out| tx_out.script_pubkey.to_bytes()).collect::<Vec<Vec<u8>>>();

    let mut v = vec![];
    for (i, script_pubkey) in script_pubkeys.iter().enumerate() {
        let script_pubkey_len = script_pubkey.len() as u32;
        let value = spent_outputs[i].value.to_sat() as i64;

        let utxo = Utxo {
            script_pubkey: script_pubkeys[i].as_ptr(),
            script_pubkey_len,
            value,
        };
        v.push(utxo);
    }

    bitcoinconsensus::verify(
        script.as_bytes(),
        amount.to_sat(),
        spending_tx,
        Some(&v),
        index,
    )
    .map_err(BitcoinconsensusError)
}

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
#[deprecated(since = "TBD", note = "use taproot specific function")]
pub fn verify_script(
    script: &Script,
    index: usize,
    amount: Amount,
    spending_tx: &[u8],
) -> Result<(), BitcoinconsensusError> {
    verify_script_with_flags(script, index, amount, spending_tx, bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT)
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
#[deprecated(since = "TBD", note = "use taproot specific function")]
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
/// Shorthand for [`consensus::verify_transaction_with_flags`] with flag
/// [`bitcoinconsensus::VERIFY_ALL`].
///
/// The `spent` closure should not return the same [`TxOut`] twice!
///
/// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
///
/// **DOES NOT VERIFY TAPROOT INPUTS**
pub fn verify_transaction<S>(tx: &Transaction, spent: S) -> Result<(), TxVerifyError>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    verify_transaction_with_flags(tx, spent, bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT)
}

/// Verifies that this transaction is able to spend its inputs.
///
/// The `spent` closure should not return the same [`TxOut`] twice!
///
/// **DOES NOT VERIFY TAPROOT INPUTS**
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
            bitcoinconsensus::verify_with_flags(
                &output.script_pubkey.as_bytes(),
                output.value.to_sat(),
                serialized_tx.as_slice(),
                None,
                idx,
                flags,
            ).map_err(BitcoinconsensusError)?;
        } else {
            return Err(TxVerifyError::UnknownSpentOutput(input.previous_output));
        }
    }
    Ok(())
}

impl Script {
    /// Verifies spend of an input script.
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///  * `spent_outputs` - List of previous outputs this script spends, `None` for pre-taproot scripts.
    ///
    /// [`bitcoinconsensus::VERIFY_ALL`]: https://docs.rs/bitcoinconsensus/0.20.2-0.5.0/bitcoinconsensus/constant.VERIFY_ALL.html
    pub fn verify(
        &self,
        index: usize,
        amount: crate::Amount,
        spending_tx: &[u8],
        spent_outputs: Option<&[TxOut]>,
    ) -> Result<(), BitcoinconsensusError> {
        match spent_outputs {
            Some(spent_outputs) => verify_taproot_script(self, index, amount, spending_tx, spent_outputs),
            None => verify_pre_taproot_script(self, index, amount, spending_tx),
        }
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
    ///
    /// **DOES NOT VERIFY TAPROOT INPUTS**
    pub fn verify<S>(&self, spent: S) -> Result<(), TxVerifyError>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        verify_transaction(self, spent)
    }

    /// Verifies that this transaction is able to spend its inputs.
    ///
    /// The `spent` closure should not return the same [`TxOut`] twice!
    ///
    /// **DOES NOT VERIFY TAPROOT INPUTS**
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

#[cfg(all(feature = "std", feature = "bitcoinconsensus-std"))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(all(feature = "std", not(feature = "bitcoinconsensus-std")))]
impl std::error::Error for BitcoinconsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
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

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;
    use crate::consensus::encode;

    #[test]
    fn verify_segwit_v1_transaction() {
        // Arbitrary Taproot transaction from block 829570
        // `bitcoin-cli getrawtransaction bce068dbd71f697e5e272b89cdc9f670e66a1d123d6ffb1751e08256d09d2300`
        let hex = "02000000000101c8cfc0a6ef444c503a6e9eee5acbe5ac7e3600bb3ce90927dce53f95f47a302e0100000000fdffffff024a01000000000000225120b60c597d6fe89e12988de69ed4d6a1a33280b8fab0f9522b3d42ea90a4bfe7e1687e06000000000022512047e54adf764198dcaedb73fa376db9367ee000d00a6e5bb78b31123f0e76a93903409fdadc7e369188dcbf42345623e58243425c8220f6a2b0d26f27a25479c4ec8586b354d4c01b3f2ebe7f3d8f52ad294b1fa0f6352e1e44b3866004422cb792ec5320462cceca2f9a552cf4f0f4420c42b95c2d75557cfa9b17c6e30a695e7eb877afac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38000d3832393536312e6269746d61706821c1462cceca2f9a552cf4f0f4420c42b95c2d75557cfa9b17c6e30a695e7eb877af00000000";
        let spending_tx = Vec::from_hex(&hex).expect("failed to parse hex");
        let tx: Transaction = encode::deserialize(&spending_tx).expect("failed to parse tx bytes");
        println!("{:#?}", tx);

        // We want to verify the first (and only) input (index 0), which has a single previous output.
        //
        // previous_output: OutPoint {
        //     txid: 0x2e307af4953fe5dc2709e93cbb00367eace5cb5aee9e6e3a504c44efa6c0cfc8,
        //     vout: 1,
        //  },
        let spend_input_index = 0;
        let vout = 1;

        // Transaction hex for the prevout we want to verify. `bitcoin-cli getrawtransaction 2e307af4953fe5dc2709e93cbb00367eace5cb5aee9e6e3a504c44efa6c0cfc8`.
        let hex = "0200000000010166583d16a93ce4f271698b3e81f7e211858d96190f3499186e7b867b20cfa5a60100000000fdffffff024a01000000000000225120fd5d688bc4f38cac778f09bc98c20d147b815677048e078b1ca49b109273fd29ce8c060000000000225120b8e58f78d713d7626fd1fdc418d845c8a1fb33a88cf12c97ef7824b8f8133f280340c883408bd38d2fabbaacc471b82a63e95273b17ad6e2c5ee690c0e5a3a67c995ffcaf17e9135a7d9af09575ac4cd45d2cd91d280f37334cfa84eab37c9ccf6f67b20462cceca2f9a552cf4f0f4420c42b95c2d75557cfa9b17c6e30a695e7eb877afac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a22646f6765222c22616d74223a2234323030227d6821c0462cceca2f9a552cf4f0f4420c42b95c2d75557cfa9b17c6e30a695e7eb877af00000000";
        let bytes = Vec::from_hex(&hex).expect("failed to parse hex");
        let tx: Transaction = encode::deserialize(&bytes).expect("failed to parse tx bytes");
        let tx_out = &tx.output[vout];

        let script = &tx_out.script_pubkey;
        let amount = tx_out.value;

        // Verify using segwit v0 verification - valid for all Taproot scripts.
        verify_pre_taproot_script(script, spend_input_index, amount, &spending_tx).unwrap();

        println!("script: {:#}", script);
        println!("amount: {:#}", amount);

        // Verify using segwit v1 verification - this example is kind
        // of trivial because we only have a single previous output.
       let spent_outputs = vec![tx_out.clone()];
       verify_taproot_script(script, spend_input_index, amount, &spending_tx, &spent_outputs).unwrap();
    }
}
