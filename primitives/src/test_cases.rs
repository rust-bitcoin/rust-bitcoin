// SPDX-License-Identifier: CC0-1.0

//! Shared test cases for the `primitives` crate.

#![allow(dead_code)]

pub(crate) mod tc {
    /// A set of test case values.
    ///
    /// Boundary cases and an arbitrary mid-range value for use in unit tests to avoid duplication
    /// and ensure consistency.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct TestCases<T> {
        pub(crate) min: T,
        /// Lower boundary plus 1.
        pub(crate) lbp1: T,
        /// An arbitrary (ideally useful) mid-range value.
        pub(crate) arbitrary: T,
        /// Upper boundary minus 1.
        pub(crate) ubm1: T,
        pub(crate) max: T,
    }

    impl<T: Copy> TestCases<T> {
        pub(crate) fn valid_values(self) -> [T; 5] { [self.min, self.lbp1, self.arbitrary, self.ubm1, self.max] }
    }

    pub(crate) const COINBASE_TX_VERSION: crate::transaction::Version = crate::transaction::Version::ONE;
    pub(crate) const COINBASE_TX_LOCK_TIME: crate::absolute::LockTime = crate::absolute::LockTime::ZERO;

    // BIP-0141 witness commitment prefix: OP_RETURN, push-36, then 0xaa21a9ed.
    pub(crate) const WITNESS_COMMITMENT_MAGIC_BYTES: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

    pub(crate) fn compact_target_cases() -> TestCases<crate::pow::CompactTarget> {
        use crate::pow::CompactTarget;

        TestCases {
            min: CompactTarget::from_consensus(0),
            lbp1: CompactTarget::from_consensus(1),
            // An arbitrary compact target with a different exponent/mantissa than the PoW limit.
            arbitrary: CompactTarget::from_consensus(0x1b04_04cb),
            // One below the Bitcoin mainnet PoW limit in compact form.
            ubm1: CompactTarget::from_consensus(0x1d00_fffe),
            // Bitcoin mainnet PoW limit / genesis difficulty bits in compact form.
            max: CompactTarget::from_consensus(0x1d00_ffff),
        }
    }

    pub(crate) fn default_header() -> crate::block::Header {
        use crate::block::{Header, Version};
        use crate::{BlockHash, BlockTime, CompactTarget, TxMerkleNode};

        Header {
            version: Version::ONE,
            // Non-zero bytes so bugs don't get masked by all-zeros.
            prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
            // Non-zero bytes so bugs don't get masked by all-zeros.
            merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
            // Small, deterministic timestamp.
            time: BlockTime::from(2),
            // Small, deterministic compact target.
            bits: CompactTarget::from_consensus(3),
            // Small, deterministic nonce.
            nonce: 4,
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn small_script_pubkey() -> crate::ScriptPubKeyBuf {
        use crate::prelude::Vec;
        use crate::ScriptPubKeyBuf;

        ScriptPubKeyBuf::from_bytes(Vec::from([1u8, 2, 3]))
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn small_script_sig() -> crate::ScriptSigBuf {
        use crate::prelude::Vec;
        use crate::ScriptSigBuf;

        ScriptSigBuf::from_bytes(Vec::from([1u8, 2, 3]))
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn one_sat_tx_out() -> crate::TxOut {
        use crate::{Amount, TxOut};

        TxOut { amount: Amount::ONE_SAT, script_pubkey: small_script_pubkey() }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn min_amount_tx_out(script_pubkey: impl AsRef<[u8]>) -> crate::TxOut {
        use crate::prelude::Vec;
        use crate::{Amount, TxOut};

        TxOut {
            amount: Amount::MIN,
            script_pubkey: crate::ScriptPubKeyBuf::from_bytes(Vec::from(script_pubkey.as_ref())),
        }
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn segwit_transaction_1in_1out() -> crate::Transaction {
        use crate::prelude::Vec;

        crate::Transaction {
            version: crate::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: Vec::from([segwit_tx_in()]),
            outputs: Vec::from([one_sat_tx_out()]),
        }
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn segwit_transaction_2in_2out() -> crate::Transaction {
        use crate::prelude::Vec;

        crate::Transaction {
            version: crate::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: Vec::from([segwit_tx_in(), segwit_tx_in()]),
            outputs: Vec::from([one_sat_tx_out(), one_sat_tx_out()]),
        }
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn non_segwit_transaction_1in_1out() -> crate::Transaction {
        use crate::prelude::Vec;
        use crate::Witness;

        let mut txin = segwit_tx_in();
        txin.witness = Witness::default();

        crate::Transaction {
            version: crate::transaction::Version::TWO,
            lock_time: crate::absolute::LockTime::ZERO,
            inputs: Vec::from([txin]),
            outputs: Vec::from([one_sat_tx_out()]),
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn coinbase_transaction(txin: crate::TxIn, outputs: crate::prelude::Vec<crate::TxOut>) -> crate::Transaction {
        use crate::prelude::Vec;

        debug_assert_eq!(txin.previous_output, crate::OutPoint::COINBASE_PREVOUT);

        crate::Transaction {
            version: COINBASE_TX_VERSION,
            lock_time: COINBASE_TX_LOCK_TIME,
            inputs: Vec::from([txin]),
            outputs,
        }
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn empty_coinbase_tx() -> crate::Transaction {
        use crate::prelude::Vec;

        coinbase_transaction(crate::TxIn::EMPTY_COINBASE, Vec::new())
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn coinbase_txin_with_witness_32(fill: u8) -> crate::TxIn {
        let mut txin = crate::TxIn::EMPTY_COINBASE;
        txin.witness.push([fill; 32]);
        txin
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn coinbase_txin_with_witness_32_and_extra(fill32: u8, extra: u8) -> crate::TxIn {
        let mut txin = coinbase_txin_with_witness_32(fill32);
        txin.witness.push([extra]);
        txin
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn witness_commitment_script_pubkey(commitment: crate::WitnessCommitment) -> crate::ScriptPubKeyBuf {
        use crate::prelude::Vec;

        let mut bytes = [0u8; 38];
        bytes[0..6].copy_from_slice(&WITNESS_COMMITMENT_MAGIC_BYTES);
        bytes[6..38].copy_from_slice(&commitment.to_byte_array());
        crate::ScriptPubKeyBuf::from_bytes(Vec::from(bytes))
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn example_out_point() -> crate::OutPoint {
        let s = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
        s.parse::<crate::OutPoint>().expect("static test outpoint parses")
    }

    #[cfg(all(feature = "alloc", any(feature = "hex", feature = "serde")))]
    pub(crate) fn segwit_tx_in() -> crate::TxIn {
        use crate::{Sequence, TxIn, Witness};

        let bytes = [1u8, 2, 3];
        let data = [&bytes[..]];
        let witness = Witness::from_iter(data);

        TxIn {
            previous_output: example_out_point(),
            script_sig: small_script_sig(),
            sequence: Sequence::MAX,
            witness,
        }
    }

    #[cfg(feature = "serde")]
    pub(crate) fn txid_from_str() -> crate::Txid {
        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
            .parse::<crate::Txid>()
            .expect("static txid parses")
    }
}
