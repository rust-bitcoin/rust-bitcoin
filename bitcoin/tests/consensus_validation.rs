use bitcoin::{absolute, TransactionVersion};

#[test]
fn verify_transaction_unknown_spent_output() {
	#[cfg(feature = "bitcoinconsensus")]
	{
		use bitcoin::consensus_validation::{verify_transaction, TxVerifyError};
		use bitcoin::{
			transaction::{OutPoint, Transaction, TxIn},
			Sequence,
			ScriptBuf,
			Witness,
		};

		// Transaction with one input referencing an outpoint that our `spent` closure won't provide.
		let tx = Transaction {
			version: TransactionVersion::TWO,
			lock_time: absolute::LockTime::ZERO,
			inputs: vec![TxIn {
				previous_output: OutPoint::COINBASE_PREVOUT,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::default(),
			}],
			outputs: vec![],
		};

		let err = verify_transaction(&tx, |_outpoint: &OutPoint| None)
			.expect_err("should error with UnknownSpentOutput");
		match err {
			TxVerifyError::UnknownSpentOutput(op) => assert_eq!(op, OutPoint::COINBASE_PREVOUT),
			other => panic!("unexpected error: {other:?}"),
		}
	}

	#[cfg(not(feature = "bitcoinconsensus"))]
	{
		// When the feature is disabled, this test is a no-op but still compiles and passes.
		assert!(true);
	}
}

#[test]
fn verify_zero_input_transaction_is_ok() {
	#[cfg(feature = "bitcoinconsensus")]
	{
		use bitcoin::consensus_validation::verify_transaction;
		use bitcoin::{
			transaction::{OutPoint, Transaction, TxOut},
			Amount,
			ScriptBuf,
		};

		// Zero-input tx should verify without consulting libconsensus (loop is empty).
		let tx = Transaction {
			version: TransactionVersion::TWO,
			lock_time: absolute::LockTime::ZERO,
			inputs: vec![],
			outputs: vec![TxOut { value: Amount::from_sat(0).unwrap(), script_pubkey: ScriptBuf::new() }],
		};

		verify_transaction(&tx, |_outpoint: &OutPoint| panic!("spent() should not be called for zero-input tx"))
			.expect("zero-input transaction should verify successfully");
	}

	#[cfg(not(feature = "bitcoinconsensus"))]
	{
		// When the feature is disabled, this test is a no-op but still compiles and passes.
		assert!(true);
	}
} 