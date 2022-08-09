// Written in 2018 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! BIP143 implementation.
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use crate::hashes::Hash;
use crate::hash_types::Sighash;
use crate::blockdata::script::Script;
use crate::blockdata::witness::Witness;
use crate::blockdata::transaction::{Transaction, EcdsaSighashType};
use crate::consensus::encode;

use crate::io;
use core::ops::{Deref, DerefMut};
use crate::util::sighash;

/// A replacement for SigHashComponents which supports all sighash modes
#[deprecated(since = "0.28.0", note = "please use [sighash::SighashCache] instead")]
pub struct SigHashCache<R: Deref<Target = Transaction>> {
    cache: sighash::SighashCache<R>,
}

#[allow(deprecated)]
impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        Self { cache: sighash::SighashCache::new(tx) }
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), encode::Error> {
        self.cache
            .segwit_encode_signing_data_to(writer, input_index, script_code, value, sighash_type)
            .expect("input_index greater than tx input len");
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type.
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType
    ) -> Sighash {
        let mut enc = Sighash::engine();
        self.encode_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        Sighash::from_engine(enc)
    }
}

#[allow(deprecated)]
impl<R: DerefMut<Target = Transaction>> SigHashCache<R> {
    /// When the SigHashCache is initialized with a mutable reference to a transaction instead of a
    /// regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    ///
    /// panics if `input_index` is out of bounds with respect of the number of inputs
    ///
    /// ```
    /// use bitcoin::blockdata::transaction::{Transaction, EcdsaSighashType};
    /// use bitcoin::util::bip143::SigHashCache;
    /// use bitcoin::{PackedLockTime, Script};
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SigHashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.signature_hash(inp, &prevout_script, 42, EcdsaSighashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.access_witness(inp).push(&[]);
    /// }
    /// ```
    pub fn access_witness(&mut self, input_index: usize) -> &mut Witness {
        self.cache.witness_mut(input_index).unwrap()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::hash_types::Sighash;
    use crate::blockdata::script::Script;
    use crate::blockdata::transaction::Transaction;
    use crate::consensus::encode::deserialize;
    use crate::hashes::hex::FromHex;
    use crate::util::sighash::SighashCache;

    use super::*;

    fn run_test_sighash_bip143(tx: &str, script: &str, input_index: usize, value: u64, hash_type: u32, expected_result: &str) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
        let raw_expected = Sighash::from_hex(expected_result).unwrap();
        let expected_result = Sighash::from_slice(raw_expected.as_ref()).unwrap();
        let mut cache = SighashCache::new(&tx);
        let sighash_type = EcdsaSighashType::from_u32_consensus(hash_type);
        let actual_result = cache.segwit_signature_hash(input_index, &script, value, sighash_type).unwrap();
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn bip143_sighash_flags() {
        // All examples generated via Bitcoin Core RPC using signrawtransactionwithwallet
        // with additional debug printing
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x01, "0a1bc2758dbb5b3a56646f8cafbf63f410cc62b77a482f8b87552683300a7711");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x02, "3e275ac8b084f79f756dcd535bffb615cc94a685eefa244d9031eaf22e4cec12");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x03, "191a08165ffacc3ea55753b225f323c35fd00d9cc0268081a4a501921fc6ec14");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x81, "4b6b612530f94470bbbdef18f57f2990d56b239f41b8728b9a49dc8121de4559");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x82, "a7e916d3acd4bb97a21e6793828279aeab02162adf8099ea4f309af81f3d5adb");
        run_test_sighash_bip143("0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000", "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac", 0, 1648888940, 0x83, "d9276e2a48648ddb53a4aaa58314fc2b8067c13013e1913ffb67e0988ce82c78");
    }
}
