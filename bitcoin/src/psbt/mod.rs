// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSBTs containing non-standard sighash types as invalid.
//!

#[macro_use]
mod macros;
mod error;
mod map;
pub mod raw;
pub mod serialize;

use core::{cmp, fmt};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use hashes::Hash;
use internals::write_err;
use secp256k1::{Keypair, Message, Secp256k1, Signing, Verification};

use crate::bip32::{self, KeySource, Xpriv, Xpub};
use crate::blockdata::transaction::{self, Transaction, TxOut};
use crate::crypto::key::{PrivateKey, PublicKey};
use crate::crypto::{ecdsa, taproot};
use crate::key::TapTweak;
use crate::prelude::*;
use crate::sighash::{self, EcdsaSighashType, Prevouts, SighashCache};
use crate::{Amount, FeeRate, TapLeafHash, TapSighashType};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    map::{Input, Output, PsbtSighashType},
    error::Error,
};

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Psbt {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpub: BTreeMap<Xpub, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    ///
    /// ## Panics
    ///
    /// The function panics if the length of transaction inputs is not equal to the length of PSBT inputs.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, Error>> {
        assert_eq!(self.inputs.len(), self.unsigned_tx.input.len());
        self.unsigned_tx.input.iter().zip(&self.inputs).map(|(tx_input, psbt_input)| {
            match (&psbt_input.witness_utxo, &psbt_input.non_witness_utxo) {
                (Some(witness_utxo), _) => Ok(witness_utxo),
                (None, Some(non_witness_utxo)) => {
                    let vout = tx_input.previous_output.vout as usize;
                    non_witness_utxo.output.get(vout).ok_or(Error::PsbtUtxoOutOfbounds)
                }
                (None, None) => Err(Error::MissingUtxo),
            }
        })
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(&self) -> Result<(), Error> {
        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(())
    }

    /// Creates a PSBT from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transactions is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error> {
        let psbt = Psbt {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],

            unsigned_tx: tx,
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        };
        psbt.unsigned_tx_checks()?;
        Ok(psbt)
    }

    /// The default `max_fee_rate` value used for extracting transactions with [`extract_tx`]
    ///
    /// As of 2023, even the biggest overpayers during the highest fee markets only paid around
    /// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(25_000);

    /// An alias for [`extract_tx_fee_rate_limit`].
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    pub fn extract_tx(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// [`ExtractTxError`] variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// See [`extract_tx`].
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    pub fn extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(max_fee_rate)
    }

    /// Perform [`extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    pub fn extract_tx_unchecked_fee_rate(self) -> Transaction { self.internal_extract_tx() }

    #[inline]
    fn internal_extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
            vin.witness = psbtin.final_script_witness.unwrap_or_default();
        }

        tx
    }

    #[inline]
    fn internal_extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        let fee = match self.fee() {
            Ok(fee) => fee,
            Err(Error::MissingUtxo) =>
                return Err(ExtractTxError::MissingInputValue { tx: self.internal_extract_tx() }),
            Err(Error::NegativeFee) => return Err(ExtractTxError::SendingTooMuch { psbt: self }),
            Err(Error::FeeOverflow) =>
                return Err(ExtractTxError::AbsurdFeeRate {
                    fee_rate: FeeRate::MAX,
                    tx: self.internal_extract_tx(),
                }),
            _ => unreachable!(),
        };

        // Note: Move prevents usage of &self from now on.
        let tx = self.internal_extract_tx();

        // Now that the extracted Transaction is made, decide how to return it.
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        // Prefer to return an AbsurdFeeRate error when both trigger.
        if fee_rate > max_fee_rate {
            return Err(ExtractTxError::AbsurdFeeRate { fee_rate, tx });
        }

        Ok(tx)
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(Error::CombineInconsistentKeySources(Box::new(xpub)));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output);
        }

        Ok(())
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeys, (SigningKeys, SigningErrors)>
    where
        C: Signing + Verification,
        K: GetKey,
    {
        let tx = self.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..self.inputs.len() {
            match self.signing_algorithm(i) {
                Ok(SigningAlgorithm::Ecdsa) =>
                    match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                        Ok(v) => {
                            used.insert(i, v);
                        }
                        Err(e) => {
                            errors.insert(i, e);
                        }
                    },
                Ok(SigningAlgorithm::Schnorr) => {
                    match self.bip32_sign_schnorr(k, i, &mut cache, secp) {
                        Ok(v) => {
                            used.insert(i, v);
                        }
                        Err(e) => {
                            errors.insert(i, e);
                        }
                    }
                }
                Err(e) => {
                    errors.insert(i, e);
                }
            }
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivation.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig = ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk.inner),
                sighash_type: sighash_ty,
            };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        Ok(used)
    }

    /// Attempts to create all signatures required by this PSBT's `tap_key_origins` field, adding
    /// them to `tap_key_sig` or `tap_script_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key. Also panics
    /// if input_index is out of bounds.
    fn bip32_sign_schnorr<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing + Verification,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let mut input = self.inputs[input_index].clone();

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (&xonly, (leaf_hashes, key_source)) in input.tap_key_origins.iter() {
            let sk = if let Ok(Some(secret_key)) =
                k.get_key(KeyRequest::Bip32(key_source.clone()), secp)
            {
                secret_key
            } else {
                continue;
            };

            // Considering the responsibility of the PSBT's finalizer to extract valid signatures,
            // the goal of this algorithm is to provide signatures to the best of our ability:
            // 1) If the conditions for key path spend are met, proceed to provide the signature for key path spend
            // 2) If the conditions for script path spend are met, proceed to provide the signature for script path spend

            // key path spend
            if let Some(internal_key) = input.tap_internal_key {
                // BIP 371: The internal key does not have leaf hashes, so can be indicated with a hashes len of 0.

                // Based on input.tap_internal_key.is_some() alone, it is not sufficient to determine whether it is a key path spend.
                // According to BIP 371, we also need to consider the condition leaf_hashes.is_empty() for a more accurate determination.
                if internal_key == xonly && leaf_hashes.is_empty() && input.tap_key_sig.is_none() {
                    let (msg, sighash_type) = self.sighash_taproot(input_index, cache, None)?;
                    let key_pair = Keypair::from_secret_key(secp, &sk.inner)
                        .tap_tweak(secp, input.tap_merkle_root)
                        .to_inner();

                    #[cfg(feature = "rand-std")]
                    let signature = secp.sign_schnorr(&msg, &key_pair);
                    #[cfg(not(feature = "rand-std"))]
                    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

                    let signature = taproot::Signature { signature, sighash_type };
                    input.tap_key_sig = Some(signature);

                    used.push(sk.public_key(secp));
                }
            }

            // script path spend
            if let Some((leaf_hashes, _)) = input.tap_key_origins.get(&xonly) {
                let leaf_hashes = leaf_hashes
                    .iter()
                    .filter(|lh| !input.tap_script_sigs.contains_key(&(xonly, **lh)))
                    .cloned()
                    .collect::<Vec<_>>();

                if !leaf_hashes.is_empty() {
                    let key_pair = Keypair::from_secret_key(secp, &sk.inner);

                    for lh in leaf_hashes {
                        let (msg, sighash_type) =
                            self.sighash_taproot(input_index, cache, Some(lh))?;

                        #[cfg(feature = "rand-std")]
                        let signature = secp.sign_schnorr(&msg, &key_pair);
                        #[cfg(not(feature = "rand-std"))]
                        let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

                        let signature = taproot::Signature { signature, sighash_type };
                        input.tap_script_sigs.insert((xonly, lh), signature);
                    }

                    used.push(sk.public_key(secp));
                }
            }
        }

        self.inputs[input_index] = input;

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        use OutputType::*;

        if self.signing_algorithm(input_index)? != SigningAlgorithm::Ecdsa {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            Bare => {
                let sighash = cache
                    .legacy_signature_hash(input_index, spk, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash = cache
                    .legacy_signature_hash(input_index, script_code, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wsh | ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash = cache
                    .p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)
                    .map_err(SignError::SegwitV0Sighash)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Tr => {
                // This PSBT signing API is WIP, taproot to come shortly.
                Err(SignError::Unsupported)
            }
        }
    }

    /// Returns the sighash message to sign an SCHNORR input along with the sighash type.
    ///
    /// Uses the [`TapSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`TapSighashType::Default`].
    fn sighash_taproot<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
        leaf_hash: Option<TapLeafHash>,
    ) -> Result<(Message, TapSighashType), SignError> {
        use OutputType::*;

        if self.signing_algorithm(input_index)? != SigningAlgorithm::Schnorr {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;

        match self.output_type(input_index)? {
            Tr => {
                let hash_ty = input
                    .sighash_type
                    .unwrap_or_else(|| TapSighashType::Default.into())
                    .taproot_hash_ty()
                    .map_err(|_| SignError::InvalidSighashType)?;

                let spend_utxos =
                    (0..self.inputs.len()).map(|i| self.spend_utxo(i).ok()).collect::<Vec<_>>();
                let all_spend_utxos;

                let is_anyone_can_pay = PsbtSighashType::from(hash_ty).to_u32() & 0x80 != 0;

                let prev_outs = if is_anyone_can_pay {
                    Prevouts::One(
                        input_index,
                        spend_utxos[input_index].ok_or(SignError::MissingSpendUtxo)?,
                    )
                } else if spend_utxos.iter().all(Option::is_some) {
                    all_spend_utxos = spend_utxos.iter().filter_map(|x| *x).collect::<Vec<_>>();
                    Prevouts::All(&all_spend_utxos)
                } else {
                    return Err(SignError::MissingSpendUtxo);
                };

                let sighash = if let Some(leaf_hash) = leaf_hash {
                    cache.taproot_script_spend_signature_hash(
                        input_index,
                        &prev_outs,
                        leaf_hash,
                        hash_ty,
                    )?
                } else {
                    cache.taproot_key_spend_signature_hash(input_index, &prev_outs, hash_ty)?
                };
                Ok((Message::from(sighash), hash_ty))
            }
            _ => Err(SignError::Unsupported),
        }
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    pub fn spend_utxo(&self, input_index: usize) -> Result<&TxOut, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = if let Some(witness_utxo) = &input.witness_utxo {
            witness_utxo
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let vout = self.unsigned_tx.input[input_index].previous_output.vout;
            &non_witness_utxo.output[vout as usize]
        } else {
            return Err(SignError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_index_is_within_bounds(input_index)?;
        Ok(&self.inputs[input_index])
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(
        &self,
        input_index: usize,
    ) -> Result<(), IndexOutOfBoundsError> {
        if input_index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs {
                index: input_index,
                length: self.inputs.len(),
            });
        }

        if input_index >= self.unsigned_tx.input.len() {
            return Err(IndexOutOfBoundsError::TxInput {
                index: input_index,
                length: self.unsigned_tx.input.len(),
            });
        }

        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if input.redeem_script.as_ref().map(|s| s.is_p2wpkh()).unwrap_or(false) {
                return Ok(OutputType::ShWpkh);
            }
            if input.redeem_script.as_ref().map(|x| x.is_p2wsh()).unwrap_or(false) {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    ///
    /// ## Errors
    ///
    /// - [`Error::MissingUtxo`] when UTXO information for any input is not present or is invalid.
    /// - [`Error::NegativeFee`] if calculated value is negative.
    /// - [`Error::FeeOverflow`] if an integer overflow occurs.
    pub fn fee(&self) -> Result<Amount, Error> {
        let mut inputs: u64 = 0;
        for utxo in self.iter_funding_utxos() {
            inputs = inputs.checked_add(utxo?.value.to_sat()).ok_or(Error::FeeOverflow)?;
        }
        let mut outputs: u64 = 0;
        for out in &self.unsigned_tx.output {
            outputs = outputs.checked_add(out.value.to_sat()).ok_or(Error::FeeOverflow)?;
        }
        inputs.checked_sub(outputs).map(Amount::from_sat).ok_or(Error::NegativeFee)
    }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-32 fingerprint and derivation path.
    Bip32(KeySource),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: core::fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == fingerprint {
                    let k = self.derive_priv(secp, &path)?;
                    Some(k.to_priv())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> pubkey associated with secret key used to create signature for that input.
pub type SigningKeys = BTreeMap<usize, Vec<PublicKey>>;

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.iter() {
                    if xpriv.parent_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(k.to_priv()));
                    }
                }
                Ok(None)
            }
        }
    }
}}}
impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_map!(HashMap);

/// Errors when getting a key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 error.
    Bip32(bip32::Error),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

internals::impl_from_infallible!(GetKeyError);

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use GetKeyError::*;

        match *self {
            Bip32(ref e) => write_err!(f, "a bip23 error"; e),
            NotSupported =>
                f.write_str("the GetKey operation is not supported for this key request"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use GetKeyError::*;

        match *self {
            NotSupported => None,
            Bip32(ref e) => Some(e),
        }
    }
}

impl From<bip32::Error> for GetKeyError {
    fn from(e: bip32::Error) -> Self { GetKeyError::Bip32(e) }
}

/// The various output types supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-witness-pubkey-hash output (P2WPKH).
    Wpkh,
    /// A pay-to-witness-script-hash output (P2WSH).
    Wsh,
    /// A nested segwit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested segwit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped segwit (P2SH).
    Sh,
    /// A taproot output (P2TR).
    Tr,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        use OutputType::*;

        match self {
            Bare | Wpkh | Wsh | ShWpkh | ShWsh | Sh => SigningAlgorithm::Ecdsa,
            Tr => SigningAlgorithm::Schnorr,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
    /// The Schnorr signature algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Schnorr_signature
    Schnorr,
}

/// Errors encountered while calculating the sighash message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// Input index out of bounds.
    IndexOutOfBounds(IndexOutOfBoundsError),
    /// Invalid Sighash type.
    InvalidSighashType,
    /// Missing input utxo.
    MissingInputUtxo,
    /// Missing Redeem script.
    MissingRedeemScript,
    /// Missing spending utxo.
    MissingSpendUtxo,
    /// Missing witness script.
    MissingWitnessScript,
    /// Signing algorithm and key type does not match.
    MismatchedAlgoKey,
    /// Attempted to ECDSA sign an non-ECDSA input.
    NotEcdsa,
    /// The `scriptPubkey` is not a P2WPKH script.
    NotWpkh,
    /// Sighash computation error (segwit v0 input).
    SegwitV0Sighash(transaction::InputsIndexError),
    /// Sighash computation error (p2wpkh input).
    P2wpkhSighash(sighash::P2wpkhError),
    /// Sighash computation error (taproot input).
    TaprootError(sighash::TaprootError),
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
}

internals::impl_from_infallible!(SignError);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SignError::*;

        match *self {
            IndexOutOfBounds(ref e) => write_err!(f, "index out of bounds"; e),
            InvalidSighashType => write!(f, "invalid sighash type"),
            MissingInputUtxo => write!(f, "missing input utxo in PBST"),
            MissingRedeemScript => write!(f, "missing redeem script"),
            MissingSpendUtxo => write!(f, "missing spend utxo in PSBT"),
            MissingWitnessScript => write!(f, "missing witness script"),
            MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            NotEcdsa => write!(f, "attempted to ECDSA sign an non-ECDSA input"),
            NotWpkh => write!(f, "the scriptPubkey is not a P2WPKH script"),
            SegwitV0Sighash(ref e) => write_err!(f, "segwit v0 sighash"; e),
            P2wpkhSighash(ref e) => write_err!(f, "p2wpkh sighash"; e),
            TaprootError(ref e) => write_err!(f, "taproot sighash"; e),
            UnknownOutputType => write!(f, "unable to determine the output type"),
            KeyNotFound => write!(f, "unable to find key"),
            WrongSigningAlgorithm =>
                write!(f, "attempt to sign an input with the wrong signing algorithm"),
            Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SignError::*;

        match *self {
            SegwitV0Sighash(ref e) => Some(e),
            P2wpkhSighash(ref e) => Some(e),
            TaprootError(ref e) => Some(e),
            IndexOutOfBounds(ref e) => Some(e),
            InvalidSighashType
            | MissingInputUtxo
            | MissingRedeemScript
            | MissingSpendUtxo
            | MissingWitnessScript
            | MismatchedAlgoKey
            | NotEcdsa
            | NotWpkh
            | UnknownOutputType
            | KeyNotFound
            | WrongSigningAlgorithm
            | Unsupported => None,
        }
    }
}

impl From<sighash::P2wpkhError> for SignError {
    fn from(e: sighash::P2wpkhError) -> Self { Self::P2wpkhSighash(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { SignError::IndexOutOfBounds(e) }
}

impl From<sighash::TaprootError> for SignError {
    fn from(e: sighash::TaprootError) -> Self { SignError::TaprootError(e) }
}

/// This error is returned when extracting a [`Transaction`] from a [`Psbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxError {
    /// The [`FeeRate`] is too high
    AbsurdFeeRate {
        /// The [`FeeRate`]
        fee_rate: FeeRate,
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// One or more of the inputs lacks value information (witness_utxo or non_witness_utxo)
    MissingInputValue {
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// Input value is less than Output Value, and the [`Transaction`] would be invalid.
    SendingTooMuch {
        /// The original [`Psbt`] is returned untouched.
        psbt: Psbt,
    },
}

internals::impl_from_infallible!(ExtractTxError);

impl fmt::Display for ExtractTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { fee_rate, .. } =>
                write!(f, "An absurdly high fee rate of {}", fee_rate),
            MissingInputValue { .. } => write!(
                f,
                "One of the inputs lacked value information (witness_utxo or non_witness_utxo)"
            ),
            SendingTooMuch { .. } => write!(
                f,
                "Transaction would be invalid due to output value being greater than input value."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { .. } | MissingInputValue { .. } | SendingTooMuch { .. } => None,
        }
    }
}

/// Input index out of bounds (actual index, maximum index allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexOutOfBoundsError {
    /// The index is out of bounds for the `psbt.inputs` vector.
    Inputs {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST inputs vector.
        length: usize,
    },
    /// The index is out of bounds for the `psbt.unsigned_tx.input` vector.
    TxInput {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST's unsigned transaction input vector.
        length: usize,
    },
}

internals::impl_from_infallible!(IndexOutOfBoundsError);

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT inputs vector length {}",
                index, length
            ),
            TxInput { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT unsigned tx input vector length {}",
                index, length
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { .. } | TxInput { .. } => None,
        }
    }
}

#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use base64::display::Base64Display;
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use internals::write_err;

    use super::{Error, Psbt};

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(Error),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(::base64::DecodeError),
    }

    internals::impl_from_infallible!(PsbtParseError);

    impl Display for PsbtParseError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PsbtParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::PsbtParseError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }

    impl Display for Psbt {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = PsbtParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(PsbtParseError::Base64Encoding)?;
            Psbt::deserialize(&data).map_err(PsbtParseError::PsbtEncoding)
        }
    }
}
#[cfg(feature = "base64")]
pub use self::display_from_str::PsbtParseError;

#[cfg(test)]
mod tests {
    use hashes::{hash160, ripemd160, sha256};
    use hex::{test_hex_unwrap as hex, FromHex};
    #[cfg(feature = "rand-std")]
    use secp256k1::{All, SecretKey};

    use super::*;
    use crate::bip32::ChildNumber;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::script::ScriptBuf;
    use crate::blockdata::transaction::{self, OutPoint, Sequence, TxIn};
    use crate::blockdata::witness::Witness;
    use crate::network::NetworkKind;
    use crate::psbt::serialize::{Deserialize, Serialize};

    #[track_caller]
    pub fn hex_psbt(s: &str) -> Result<Psbt, crate::psbt::error::Error> {
        let r = Vec::from_hex(s);
        match r {
            Err(_e) => panic!("unable to parse hex string {}", s),
            Ok(v) => Psbt::deserialize(&v),
        }
    }

    #[track_caller]
    fn psbt_with_values(input: u64, output: u64) -> Psbt {
        Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(output),
                    script_pubkey: ScriptBuf::from_hex(
                        "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                    )
                    .unwrap(),
                }],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(input),
                    script_pubkey: ScriptBuf::from_hex(
                        "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                    )
                    .unwrap(),
                }),
                ..Default::default()
            }],
            outputs: vec![],
        }
    }

    #[test]
    fn trivial_psbt() {
        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt: Psbt = hex_psbt("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();
        assert!(psbt.inputs[0].partial_sigs.len() == 1);
        let pk = psbt.inputs[0].partial_sigs.iter().next().unwrap().0;
        assert!(!pk.compressed);
    }

    #[test]
    fn psbt_high_fee_checks() {
        let psbt = psbt_with_values(5_000_000_000_000, 1000);
        assert_eq!(
            psbt.clone().extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert_eq!(
            psbt.clone().extract_tx_fee_rate_limit().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert_eq!(
            psbt.clone()
                .extract_tx_with_fee_rate_limit(FeeRate::from_sat_per_kwu(15060240960842))
                .map_err(|e| match e {
                    ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                    _ => panic!(""),
                }),
            Err(FeeRate::from_sat_per_kwu(15060240960843))
        );
        assert!(psbt
            .extract_tx_with_fee_rate_limit(FeeRate::from_sat_per_kwu(15060240960843))
            .is_ok());

        // Testing that extract_tx will error at 25k sat/vbyte (6250000 sat/kwu)
        assert_eq!(
            psbt_with_values(2076001, 1000).extract_tx().map_err(|e| match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => fee_rate,
                _ => panic!(""),
            }),
            Err(FeeRate::from_sat_per_kwu(6250003)) // 6250000 is 25k sat/vbyte
        );

        // Lowering the input satoshis by 1 lowers the sat/kwu by 3
        // Putting it exactly at 25k sat/vbyte
        assert!(psbt_with_values(2076000, 1000).extract_tx().is_ok());
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = Default::default();

        let mut sk: Xpriv = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();

        let fprint = sk.fingerprint(secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_priv(secp, &dpath).unwrap();

        let pk = Xpub::from_priv(secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(
                ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
            ),
            witness_script: Some(
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
            ),
            bip32_derivation: hd_keypaths,
            ..Default::default()
        };

        let actual = Output::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::default(),
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(99_999_699),
                        script_pubkey: ScriptBuf::from_hex(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                        )
                        .unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat(100_000_000),
                        script_pubkey: ScriptBuf::from_hex(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                        )
                        .unwrap(),
                    },
                ],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],
        };

        let actual: Psbt = Psbt::deserialize(&expected.serialize()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key { type_value: 0u8, key: vec![42u8, 69u8] },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual = raw::Pair::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn deserialize_and_serialize_psbt_with_two_partial_sigs() {
        let hex = "70736274ff0100890200000001207ae985d787dfe6143d5c58fad79cc7105e0e799fcf033b7f2ba17e62d7b3200000000000ffffffff02563d03000000000022002019899534b9a011043c0dd57c3ff9a381c3522c5f27c6a42319085b56ca543a1d6adc020000000000220020618b47a07ebecca4e156edb1b9ea7c24bdee0139fc049237965ffdaf56d5ee73000000000001012b801a0600000000002200201148e93e9315e37dbed2121be5239257af35adc03ffdfc5d914b083afa44dab82202025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee076473044022007e06b362e89912abd4661f47945430739b006a85d1b2a16c01dc1a4bd07acab022061576d7aa834988b7ab94ef21d8eebd996ea59ea20529a19b15f0c9cebe3d8ac01220202b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a473044022002787f926d6817504431ee281183b8119b6845bfaa6befae45e13b6d430c9d2f02202859f149a6cd26ae2f03a107e7f33c7d91730dade305fe077bae677b5d44952a01010547522102b3fe93530020a8294f0e527e33fbdff184f047eb6b5a1558a352f62c29972f8a21025fe7371376d53cf8a2783917c28bf30bd690b0a4d4a207690093ca2b920ee07652ae0001014752210283ef76537f2d58ae3aa3a4bd8ae41c3f230ccadffb1a0bd3ca504d871cff05e7210353d79cc0cb1396f4ce278d005f16d948e02a6aec9ed1109f13747ecb1507b37b52ae00010147522102b3937241777b6665e0d694e52f9c1b188433641df852da6fc42187b5d8a368a321034cdd474f01cc5aa7ff834ad8bcc882a87e854affc775486bc2a9f62e8f49bd7852ae00";
        let psbt: Psbt = hex_psbt(hex).unwrap();
        assert_eq!(hex, psbt.serialize_hex());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_psbt() {
        //! Create a full PSBT value with various fields filled and make sure it can be JSONized.
        use hashes::sha256d;

        use crate::psbt::map::Input;

        // create some values to use in the PSBT
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
                        .parse()
                        .unwrap(),
                    vout: 1,
                },
                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                    .unwrap(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[hex!(
                    "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
                )]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(190_303_501_938),
                script_pubkey: ScriptBuf::from_hex(
                    "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                )
                .unwrap(),
            }],
        };
        let unknown: BTreeMap<raw::Key, Vec<u8>> =
            vec![(raw::Key { type_value: 1, key: vec![0, 1] }, vec![3, 4, 5])]
                .into_iter()
                .collect();
        let key_source = ("deadbeef".parse().unwrap(), "0'/1".parse().unwrap());
        let keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = vec![(
            "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
            key_source.clone(),
        )]
        .into_iter()
        .collect();

        let proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = vec![(
            raw::ProprietaryKey {
                prefix: "prefx".as_bytes().to_vec(),
                subtype: 42,
                key: "test_key".as_bytes().to_vec(),
            },
            vec![5, 6, 7],
        )]
        .into_iter()
        .collect();

        let psbt = Psbt {
            version: 0,
            xpub: {
                let xpub: Xpub =
                    "xpub661MyMwAqRbcGoRVtwfvzZsq2VBJR1LAHfQstHUoxqDorV89vRoMxUZ27kLrraAj6MPi\
                    QfrDb27gigC1VS1dBXi5jGpxmMeBXEkKkcXUTg4".parse().unwrap();
                vec![(xpub, key_source)].into_iter().collect()
            },
            unsigned_tx: {
                let mut unsigned = tx.clone();
                unsigned.input[0].script_sig = ScriptBuf::new();
                unsigned.input[0].witness = Witness::default();
                unsigned
            },
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(tx),
                    witness_utxo: Some(TxOut {
                        value: Amount::from_sat(190_303_501_938),
                        script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                    }),
                    sighash_type: Some("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY".parse::<PsbtSighashType>().unwrap()),
                    redeem_script: Some(vec![0x51].into()),
                    witness_script: None,
                    partial_sigs: vec![(
                        "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
                        "304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe701".parse().unwrap(),
                    )].into_iter().collect(),
                    bip32_derivation: keypaths.clone(),
                    final_script_witness: Some(Witness::from_slice(&[vec![1, 3], vec![5]])),
                    ripemd160_preimages: vec![(ripemd160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    sha256_preimages: vec![(sha256::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash160_preimages: vec![(hash160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash256_preimages: vec![(sha256d::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    proprietary: proprietary.clone(),
                    unknown: unknown.clone(),
                    ..Default::default()
                }
            ],
            outputs: vec![
                Output {
                    bip32_derivation: keypaths,
                    proprietary,
                    unknown,
                    ..Default::default()
                }
            ],
        };
        let encoded = serde_json::to_string(&psbt).unwrap();
        let decoded: Psbt = serde_json::from_str(&encoded).unwrap();
        assert_eq!(psbt, decoded);
    }

    mod bip_vectors {
        #[cfg(feature = "base64")]
        use std::str::FromStr;

        use super::*;
        use crate::psbt::map::Map;

        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1() {
            hex_psbt("0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1_base64() {
            Psbt::from_str("AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==").unwrap();
        }

        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2() {
            hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000")
                .unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2_base64() {
            Psbt::from_str("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==")
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3() {
            hex_psbt("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3_base64() {
            Psbt::from_str("cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA=").unwrap();
        }

        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4() {
            hex_psbt("70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4_base64() {
            Psbt::from_str("cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==").unwrap();
        }

        #[test]
        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key: [] })")]
        fn invalid_vector_5() {
            hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key: [] })")]
        fn invalid_vector_5_base64() {
            Psbt::from_str("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA").unwrap();
        }

        #[test]
        fn valid_vector_1() {
            let unserialized = Psbt {
                unsigned_tx: Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::from_consensus(1257139),
                    input: vec![
                        TxIn {
                            previous_output: OutPoint {
                                txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                                vout: 0,
                            },
                            script_sig: ScriptBuf::new(),
                            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                            witness: Witness::default(),
                        }
                    ],
                    output: vec![
                        TxOut {
                            value: Amount::from_sat(99_999_699),
                            script_pubkey: ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                        },
                        TxOut {
                            value: Amount::from_sat(100_000_000),
                            script_pubkey: ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                        },
                    ],
                },
                xpub: Default::default(),
                version: 0,
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),

                inputs: vec![
                    Input {
                        non_witness_utxo: Some(Transaction {
                            version: transaction::Version::ONE,
                            lock_time: absolute::LockTime::ZERO,
                            input: vec![
                                TxIn {
                                    previous_output: OutPoint {
                                        txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                        vout: 1,
                                    },
                                    script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                    sequence: Sequence::MAX,
                                    witness: Witness::from_slice(&[
                                        hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01"),
                                        hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"),
                                    ]),
                                },
                                TxIn {
                                    previous_output: OutPoint {
                                        txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                        vout: 1,
                                    },
                                    script_sig: ScriptBuf::from_hex("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                    sequence: Sequence::MAX,
                                    witness: Witness::from_slice(&[
                                        hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01"),
                                        hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"),
                                    ]),
                                }
                            ],
                            output: vec![
                                TxOut {
                                    value: Amount::from_sat(200_000_000),
                                    script_pubkey: ScriptBuf::from_hex("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                                },
                                TxOut {
                                    value: Amount::from_sat(190_303_501_938),
                                    script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                                },
                            ],
                        }),
                        ..Default::default()
                    },
                ],
                outputs: vec![
                    Output {
                        ..Default::default()
                    },
                    Output {
                        ..Default::default()
                    },
                ],
            };

            let base16str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";

            assert_eq!(unserialized.serialize_hex(), base16str);
            assert_eq!(unserialized, hex_psbt(base16str).unwrap());

            #[cfg(feature = "base64")]
            {
                let base64str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
                assert_eq!(Psbt::from_str(base64str).unwrap(), unserialized);
                assert_eq!(base64str, unserialized.to_string());
                assert_eq!(Psbt::from_str(base64str).unwrap(), hex_psbt(base16str).unwrap());
            }
        }

        #[test]
        fn valid_vector_2() {
            let psbt: Psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_some());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.outputs {
                assert_eq!(output.get_pairs().len(), 0)
            }
        }

        #[test]
        fn valid_vector_3() {
            let psbt: Psbt = hex_psbt("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);

            let tx_input = &psbt.unsigned_tx.input[0];
            let psbt_non_witness_utxo = psbt.inputs[0].non_witness_utxo.as_ref().unwrap();

            assert_eq!(tx_input.previous_output.txid, psbt_non_witness_utxo.compute_txid());
            assert!(psbt_non_witness_utxo.output[tx_input.previous_output.vout as usize]
                .script_pubkey
                .is_p2pkh());
            assert_eq!(
                psbt.inputs[0].sighash_type.as_ref().unwrap().ecdsa_hash_ty().unwrap(),
                EcdsaSighashType::All
            );
        }

        #[test]
        fn valid_vector_4() {
            let psbt: Psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_none());
            assert!(&psbt.inputs[1].final_script_sig.is_none());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.outputs {
                assert!(!output.get_pairs().is_empty())
            }
        }

        #[test]
        fn valid_vector_5() {
            let psbt: Psbt = hex_psbt("70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            assert!(&psbt.inputs[0].final_script_sig.is_none());

            let redeem_script = psbt.inputs[0].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87").unwrap();

            assert!(redeem_script.is_p2wsh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey
            );

            assert_eq!(redeem_script.to_p2sh(), expected_out);
        }

        #[test]
        fn valid_vector_6() {
            let psbt: Psbt = hex_psbt("70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a0f0102030405060708090f0102030405060708090a0b0c0d0e0f0000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            let tx = &psbt.unsigned_tx;
            assert_eq!(
                tx.compute_txid(),
                "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115".parse().unwrap(),
            );

            let mut unknown: BTreeMap<raw::Key, Vec<u8>> = BTreeMap::new();
            let key: raw::Key = raw::Key { type_value: 0x0fu8, key: hex!("010203040506070809") };
            let value: Vec<u8> = hex!("0102030405060708090a0b0c0d0e0f");

            unknown.insert(key, value);

            assert_eq!(psbt.inputs[0].unknown, unknown)
        }
    }

    mod bip_371_vectors {
        use super::*;

        #[test]
        fn invalid_vectors() {
            let err = hex_psbt("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a075701172102fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757011342173bb3d36c074afb716fec6307a069a2e450b995f3c82785945ab8df0e24260dcd703b0cbf34de399184a9481ac2b3586db6601f026a77f7e4938481bc34751701aa000000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 66"
            );
            let err = hex_psbt("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757221602fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt("70736274ff01007d020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02887b0100000000001600142382871c7e8421a00093f754d91281e675874b9f606b042a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000001052102fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa23200").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt("70736274ff01007d020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02887b0100000000001600142382871c7e8421a00093f754d91281e675874b9f606b042a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07570000220702fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da7560000800100008000000080010000000000000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6924214022cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b094089756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb0000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid hash when parsing slice");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid hash when parsing slice: invalid slice length 33 (expected 32)"
            );
            let err = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b094289756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb01010000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 66"
            );
            let err = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b093989756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb0000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 57"
            );
            let err = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926315c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f80023202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc00000").unwrap_err();
            assert_eq!(err.to_string(), "invalid control block");
            let err = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926115c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e123202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc00000").unwrap_err();
            assert_eq!(err.to_string(), "invalid control block");
        }

        fn rtt_psbt(psbt: Psbt) {
            let enc = Psbt::serialize(&psbt);
            let psbt2 = Psbt::deserialize(&enc).unwrap();
            assert_eq!(psbt, psbt2);
        }

        #[test]
        fn valid_psbt_vectors() {
            let psbt = hex_psbt("70736274ff010052020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a01000000160014768e1eeb4cf420866033f80aceff0f9720744969000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232002202036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d818772b2da7540000800100008000000080000000000000000000").unwrap();
            let internal_key = psbt.inputs[0].tap_internal_key.unwrap();
            assert!(psbt.inputs[0].tap_key_origins.contains_key(&internal_key));
            rtt_psbt(psbt);

            // vector 2
            let psbt = hex_psbt("70736274ff010052020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a01000000160014768e1eeb4cf420866033f80aceff0f9720744969000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757011340bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af342116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232002202036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d818772b2da7540000800100008000000080000000000000000000").unwrap();
            let internal_key = psbt.inputs[0].tap_internal_key.unwrap();
            assert!(psbt.inputs[0].tap_key_origins.contains_key(&internal_key));
            assert!(psbt.inputs[0].tap_key_sig.is_some());
            rtt_psbt(psbt);

            // vector 3
            let psbt = hex_psbt("70736274ff01005e020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            let internal_key = psbt.outputs[0].tap_internal_key.unwrap();
            assert!(psbt.outputs[0].tap_key_origins.contains_key(&internal_key));
            rtt_psbt(psbt);

            // vector 4
            let psbt = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f823202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc04215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac097c6e6fea5ff714ff5724499990810e406e98aa10f5bf7e5f6784bc1d0a9a6ce23204320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2acc06215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f82320fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9acc021162cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d23901cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09772b2da7560000800100008002000080000000000000000021164320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b23901115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8772b2da75600008001000080010000800000000000000000211650929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2116fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca939016f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970772b2da7560000800100008003000080000000000000000001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0011820f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            assert!(psbt.inputs[0].tap_internal_key.is_some());
            assert!(psbt.inputs[0].tap_merkle_root.is_some());
            assert!(!psbt.inputs[0].tap_key_origins.is_empty());
            assert!(!psbt.inputs[0].tap_scripts.is_empty());
            rtt_psbt(psbt);

            // vector 5
            let psbt = hex_psbt("70736274ff01005e020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a010000002251200a8cbdc86de1ce1c0f9caeb22d6df7ced3683fe423e05d1e402a879341d6f6f5000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2320001052050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac001066f02c02220736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac02c02220631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac01c0222044faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273ac210744faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c42733901f06b798b92a10ed9a9d0bbfd3af173a53b1617da3a4159ca008216cd856b2e0e772b2da75600008001000080010000800000000003000000210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2107631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969390118ace409889785e0ea70ceebb8e1ca892a7a78eaede0f2e296cf435961a8f4ca772b2da756000080010000800200008000000000030000002107736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02390129a5b4915090162d759afd3fe0f93fa3326056d0b4088cb933cae7826cb8d82c772b2da7560000800100008003000080000000000300000000").unwrap();
            assert!(psbt.outputs[0].tap_internal_key.is_some());
            assert!(!psbt.outputs[0].tap_key_origins.is_empty());
            assert!(psbt.outputs[0].tap_tree.is_some());
            rtt_psbt(psbt);

            // vector 6
            let psbt = hex_psbt("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b0940bf818d9757d6ffeb538ba057fb4c1fc4e0f5ef186e765beb564791e02af5fd3d5e2551d4e34e33d86f276b82c99c79aed3f0395a081efcd2cc2c65dd7e693d7941144320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f840e1f1ab6fabfa26b236f21833719dc1d428ab768d80f91f9988d8abef47bfb863bb1f2a529f768c15f00ce34ec283cdc07e88f8428be28f6ef64043c32911811a4114fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca96f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae97040ec1f0379206461c83342285423326708ab031f0da4a253ee45aafa5b8c92034d8b605490f8cd13e00f989989b97e215faa36f12dee3693d2daccf3781c1757f66215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f823202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc04215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac097c6e6fea5ff714ff5724499990810e406e98aa10f5bf7e5f6784bc1d0a9a6ce23204320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2acc06215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f82320fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9acc021162cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d23901cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09772b2da7560000800100008002000080000000000000000021164320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b23901115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8772b2da75600008001000080010000800000000000000000211650929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2116fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca939016f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970772b2da7560000800100008003000080000000000000000001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0011820f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            assert!(psbt.inputs[0].tap_internal_key.is_some());
            assert!(psbt.inputs[0].tap_merkle_root.is_some());
            assert!(!psbt.inputs[0].tap_scripts.is_empty());
            assert!(!psbt.inputs[0].tap_script_sigs.is_empty());
            assert!(!psbt.inputs[0].tap_key_origins.is_empty());
            rtt_psbt(psbt);
        }
    }

    #[test]
    fn serialize_and_deserialize_preimage_psbt() {
        // create a sha preimage map
        let mut sha256_preimages = BTreeMap::new();
        sha256_preimages.insert(sha256::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        sha256_preimages.insert(sha256::Hash::hash(&[1u8]), vec![1u8]);

        // same for hash160
        let mut hash160_preimages = BTreeMap::new();
        hash160_preimages.insert(hash160::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        hash160_preimages.insert(hash160::Hash::hash(&[1u8]), vec![1u8]);

        // same vector as valid_vector_1 from BIPs with added
        let mut unserialized = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        witness: Witness::default(),
                    }
                ],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(99_999_699),
                        script_pubkey: ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                    },
                    TxOut {
                        value: Amount::from_sat(100_000_000),
                        script_pubkey: ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                    },
                ],
            },
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01"),
                                    hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"),
                                ]),
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                sequence: Sequence::MAX,
                                witness: Witness::from_slice(&[
                                    hex!("3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01"),
                                    hex!("0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"),
                                ]),
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: Amount::from_sat(200_000_000),
                                script_pubkey: ScriptBuf::from_hex("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938),
                                script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;

        let rtt: Psbt = hex_psbt(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<Psbt, _> = hex_psbt(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietary() {
        let mut psbt: Psbt = hex_psbt("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.proprietary.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0u8, key: b"test".to_vec() },
            b"test".to_vec(),
        );
        assert!(!psbt.proprietary.is_empty());
        let rtt: Psbt = hex_psbt(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.proprietary.is_empty());
    }

    // PSBTs taken from BIP 174 test vectors.
    #[test]
    fn combine_psbts() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();
        let psbt_combined = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        psbt1.combine(psbt2).expect("psbt combine to succeed");
        assert_eq!(psbt1, psbt_combined);
    }

    #[test]
    fn combine_psbts_commutative() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let mut psbt2 = hex_psbt(include_str!("../../tests/data/psbt2.hex")).unwrap();

        let psbt1_clone = psbt1.clone();
        let psbt2_clone = psbt2.clone();

        psbt1.combine(psbt2_clone).expect("psbt1 combine to succeed");
        psbt2.combine(psbt1_clone).expect("psbt2 combine to succeed");

        assert_eq!(psbt1, psbt2);
    }

    #[cfg(feature = "rand-std")]
    fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<All>) {
        use secp256k1::rand::thread_rng;

        let secp = Secp256k1::new();

        let sk = SecretKey::new(&mut thread_rng());
        let priv_key = PrivateKey::new(sk, NetworkKind::Test);
        let pk = PublicKey::from_private_key(&secp, &priv_key);

        (priv_key, pk, secp)
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn get_key_btree_map() {
        let (priv_key, pk, secp) = gen_keys();

        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        let got = key_map.get_key(KeyRequest::Pubkey(pk), &secp).expect("failed to get key");
        assert_eq!(got.unwrap(), priv_key)
    }

    #[test]
    fn test_fee() {
        let output_0_val = Amount::from_sat(99_999_699);
        let output_1_val = Amount::from_sat(100_000_000);
        let prev_output_val = Amount::from_sat(200_000_000);

        let mut t = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_consensus(1257139),
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        ..Default::default()
                    }
                ],
                output: vec![
                    TxOut {
                        value: output_0_val,
                        script_pubkey:  ScriptBuf::new()
                    },
                    TxOut {
                        value: output_1_val,
                        script_pubkey:  ScriptBuf::new()
                    },
                ],
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: transaction::Version::ONE,
                        lock_time: absolute::LockTime::ZERO,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..Default::default()
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..Default::default()
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: prev_output_val,
                                script_pubkey:  ScriptBuf::new()
                            },
                            TxOut {
                                value: Amount::from_sat(190_303_501_938),
                                script_pubkey:  ScriptBuf::new()
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            t.fee().expect("fee calculation"),
            prev_output_val - (output_0_val + output_1_val)
        );
        // no previous output
        let mut t2 = t.clone();
        t2.inputs[0].non_witness_utxo = None;
        match t2.fee().unwrap_err() {
            Error::MissingUtxo => {}
            e => panic!("unexpected error: {:?}", e),
        }
        //  negative fee
        let mut t3 = t.clone();
        t3.unsigned_tx.output[0].value = prev_output_val;
        match t3.fee().unwrap_err() {
            Error::NegativeFee => {}
            e => panic!("unexpected error: {:?}", e),
        }
        // overflow
        t.unsigned_tx.output[0].value = Amount::MAX;
        t.unsigned_tx.output[1].value = Amount::MAX;
        match t.fee().unwrap_err() {
            Error::FeeOverflow => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_psbt() {
        use crate::bip32::{DerivationPath, Fingerprint};
        use crate::witness_version::WitnessVersion;
        use crate::{WPubkeyHash, WitnessProgram};

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let (priv_key, pk, secp) = gen_keys();

        // key_map implements `GetKey` using KeyRequest::Pubkey. A pubkey key request does not use
        // keysource so we use default `KeySource` (fingreprint and derivation path) below.
        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        // First input we can spend. See comment above on key_map for why we use defaults here.
        let txout_wpkh = TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&pk.to_bytes())),
        };
        psbt.inputs[0].witness_utxo = Some(txout_wpkh);

        let mut map = BTreeMap::new();
        map.insert(pk.inner, (Fingerprint::default(), DerivationPath::default()));
        psbt.inputs[0].bip32_derivation = map;

        // Second input is unspendable by us e.g., from another wallet that supports future upgrades.
        let unknown_prog = WitnessProgram::new(WitnessVersion::V4, &[0xaa; 34]).unwrap();
        let txout_unknown_future = TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::new_witness_program(&unknown_prog),
        };
        psbt.inputs[1].witness_utxo = Some(txout_unknown_future);

        let (signing_keys, _) = psbt.sign(&key_map, &secp).unwrap_err();

        assert_eq!(signing_keys.len(), 1);
        assert_eq!(signing_keys[&0], vec![pk]);
    }
}
