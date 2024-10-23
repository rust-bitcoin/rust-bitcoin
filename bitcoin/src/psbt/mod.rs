// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSBTs containing non-standard sighash types as invalid.

#[macro_use]
mod macros;
mod consts;
pub mod input;
pub mod output;
pub mod serialize;
pub mod sighash_type;
mod signer_checks;
mod version;

use core::convert::Infallible;
use core::{cmp, fmt};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use internals::write_err;
use io::{self, Write};
use secp256k1::{Keypair, Message, Secp256k1, Signing, Verification};

use self::serialize::{map, raw};
use crate::bip32::{self, DerivationPath, KeySource, Xpriv, Xpub};
use crate::crypto::key::{PrivateKey, PublicKey};
use crate::crypto::{ecdsa, taproot};
use crate::key::{TapTweak, XOnlyPublicKey};
use crate::prelude::{btree_map, BTreeMap, BTreeSet, Borrow, Box, String, Vec};
use crate::script::ScriptExt as _;
use crate::sighash::{self, EcdsaSighashType, Prevouts, SighashCache};
use crate::transaction::{self, Transaction, TransactionExt as _, TxOut};
use crate::{Amount, FeeRate, TapLeafHash, TapSighashType};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    serialize::map::{PsbtInvalidError, PsbtV0InvalidError, PsbtV2InvalidError, InputV0InvalidError, InputV2InvalidError, OutputV0InvalidError, OutputV2InvalidError},
    input::{Input, InvalidError as InputInvalidError},
    output::{Output, InvalidError as OutputInvalidError},
    serialize::Error,
    sighash_type::PsbtSighashType,
    version::{Version, UnsupportedVersionError},
};
#[cfg(feature = "base64")]
pub use self::serialize::map::PsbtParseError;

/// A Partially Signed Bitcoin Transaction (PSBT).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,

    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: Version,

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
    /// Creates a `Psbt` from a serializable [`Psbt`].
    ///
    /// [`Psbt`]: crate::psbt::map::Psbt
    pub fn from_serializable(psbt: map::Psbt) -> Result<Self, PsbtInvalidError> {
        psbt.assert_valid()?;

        Ok(Self {
            unsigned_tx: psbt.unsigned_tx.unwrap(),
            version: psbt.version,
            xpub: psbt.xpub,
            proprietary: psbt.proprietary,
            unknown: psbt.unknown,
            inputs: psbt
                .inputs
                .into_iter()
                .map(Input::from_serializable)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(), // Inputs are guaranteed valid by assert_valid
            outputs: psbt
                .outputs
                .into_iter()
                .map(Output::from_serializable)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(), // Inputs are guaranteed valid by assert_valid
        })
    }

    /// Converts this `Psbt` into a serializable [`Psbt`].
    ///
    /// [`Psbt`]: crate::psbt::map::Psbt
    pub fn into_serializable(self) -> map::Psbt {
        let tx_version = self.unsigned_tx.version;

        map::Psbt {
            unsigned_tx: Some(self.unsigned_tx),
            xpub: self.xpub,
            tx_version: Some(tx_version),
            fallback_lock_time: None,
            input_count: None,
            output_count: None,
            tx_modifiable_flags: None,
            version: self.version,
            proprietary: self.proprietary,
            unknown: self.unknown,
            inputs: self.inputs.into_iter().map(|input| input.into_serializable()).collect(),
            outputs: self.outputs.into_iter().map(|output| output.into_serializable()).collect(),
        }
    }

    /// Serialize a value as bytes in hex.
    // TODO: Remove the clone without consuming self.
    pub fn serialize_hex(&self) -> String { self.clone().into_serializable().serialize_hex() }

    /// Serialize as raw binary data
    // TODO: Remove the clone without consuming self.
    pub fn serialize(&self) -> Vec<u8> { self.clone().into_serializable().serialize() }

    /// Serialize the PSBT into a writer.
    // TODO: Remove the clone without consuming self.
    pub fn serialize_to_writer(&self, w: &mut impl Write) -> io::Result<usize> {
        self.clone().into_serializable().serialize_to_writer(w)
    }

    /// Deserialize a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let psbt = map::Psbt::deserialize(bytes)?;
        Ok(Self::from_serializable(psbt)?)
    }

    /// Deserialize a value from raw binary data read from a `BufRead` object.
    pub fn deserialize_from_reader<R: io::BufRead>(r: &mut R) -> Result<Self, DeserializeError> {
        let psbt = map::Psbt::deserialize_from_reader(r)?;
        Ok(Self::from_serializable(psbt)?)
    }

    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// # Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    ///
    /// # Panics
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

    /// Constructs a new PSBT from an unsigned transaction.
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
            version: Version::Zero,
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
    /// # Errors
    ///
    /// [`ExtractTxError`] variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// # Errors
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
                    } else if derivation2.len() <= derivation1.len()
                        && derivation2[..] == derivation1[derivation1.len() - derivation2.len()..]
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
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa` or
    /// `sighash_taproot`. This function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// A map of input index -> keys used to sign, for Taproot specifics please see [`SigningKeys`].
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeysMap, (SigningKeysMap, SigningErrors)>
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
                            used.insert(i, SigningKeys::Ecdsa(v));
                        }
                        Err(e) => {
                            errors.insert(i, e);
                        }
                    },
                Ok(SigningAlgorithm::Schnorr) => {
                    match self.bip32_sign_schnorr(k, i, &mut cache, secp) {
                        Ok(v) => {
                            used.insert(i, SigningKeys::Schnorr(v));
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
            let sk = if let Ok(Some(sk)) = k.get_key(&KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(&KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
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
    /// - Ok: A list of the xonly public keys used in signing. When signing a key path spend we
    ///   return the internal key.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_schnorr<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<XOnlyPublicKey>, SignError>
    where
        C: Signing + Verification,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let mut input = self.checked_input(input_index)?.clone();

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (&xonly, (leaf_hashes, key_source)) in input.tap_key_origins.iter() {
            let sk = if let Ok(Some(secret_key)) =
                k.get_key(&KeyRequest::Bip32(key_source.clone()), secp)
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

                    used.push(internal_key);
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

                    used.push(sk.public_key(secp).into());
                }
            }
        }

        self.inputs[input_index] = input; // input_index is checked above.

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
                Ok((Message::from(sighash), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash = cache
                    .legacy_signature_hash(input_index, script_code, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                Ok((Message::from(sighash), hash_ty))
            }
            ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                Ok((Message::from(sighash), hash_ty))
            }
            Wsh | ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash = cache
                    .p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)
                    .map_err(SignError::SegwitV0Sighash)?;
                Ok((Message::from(sighash), hash_ty))
            }
            Tr => {
                // This PSBT signing API is WIP, Taproot to come shortly.
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
        // No `?` operator in const context.
        match self.check_index_is_within_bounds(input_index) {
            Ok(_) => Ok(&self.inputs[input_index]),
            Err(e) => Err(e),
        }
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

        // Anything that is not SegWit and is not p2sh is `Bare`.
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
    /// # Errors
    ///
    /// - [`Error::MissingUtxo`] when UTXO information for any input is not present or is invalid.
    /// - [`Error::NegativeFee`] if calculated value is negative.
    /// - [`Error::FeeOverflow`] if an integer overflow occurs.
    pub fn fee(&self) -> Result<Amount, Error> {
        let mut inputs = Amount::ZERO;
        for utxo in self.iter_funding_utxos() {
            inputs = inputs.checked_add(utxo?.value).ok_or(Error::FeeOverflow)?;
        }
        let mut outputs = Amount::ZERO;
        for out in &self.unsigned_tx.output {
            outputs = outputs.checked_add(out.value).ok_or(Error::FeeOverflow)?;
        }
        inputs.checked_sub(outputs).ok_or(Error::NegativeFee)
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
    ///
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == *fingerprint {
                    let k = self.derive_xpriv(secp, &path);
                    Some(k.to_private_key())
                } else if self.parent_fingerprint == *fingerprint
                    && !path.is_empty()
                    && path[0] == self.child_number
                {
                    let path = DerivationPath::from_iter(path.into_iter().skip(1).copied());
                    let k = self.derive_xpriv(secp, &path);
                    Some(k.to_private_key())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> signing key for that input (see [`SigningKeys`]).
pub type SigningKeysMap = BTreeMap<usize, SigningKeys>;

/// A list of keys used to sign an input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKeys {
    /// Keys used to sign an ECDSA input.
    Ecdsa(Vec<PublicKey>),
    /// Keys used to sign a Taproot input.
    ///
    /// - Key path spend: This is the internal key.
    /// - Script path spend: This is the pubkey associated with the secret key that signed.
    Schnorr(Vec<XOnlyPublicKey>),
}

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        // OK to stop at the first error because Xpriv::get_key() can only fail
        // if this isn't a KeyRequest::Bip32, which would fail for all Xprivs.
        self.iter()
            .find_map(|xpriv| xpriv.get_key(key_request, secp).transpose())
            .transpose()
    }
}}}
impl_get_key_for_set!(Vec);
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
        key_request: &KeyRequest,
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

impl From<Infallible> for GetKeyError {
    fn from(never: Infallible) -> Self { match never {} }
}

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
    /// A nested SegWit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested SegWit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped SegWit (P2SH).
    Sh,
    /// A Taproot output (P2TR).
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
    /// Sighash computation error (SegWit v0 input).
    SegwitV0Sighash(transaction::InputsIndexError),
    /// Sighash computation error (p2wpkh input).
    P2wpkhSighash(sighash::P2wpkhError),
    /// Sighash computation error (Taproot input).
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

impl From<Infallible> for SignError {
    fn from(never: Infallible) -> Self { match never {} }
}

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
            SegwitV0Sighash(ref e) => write_err!(f, "SegWit v0 sighash"; e),
            P2wpkhSighash(ref e) => write_err!(f, "p2wpkh sighash"; e),
            TaprootError(ref e) => write_err!(f, "Taproot sighash"; e),
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

impl From<Infallible> for ExtractTxError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ExtractTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { fee_rate, .. } =>
                write!(f, "an absurdly high fee rate of {}", fee_rate),
            MissingInputValue { .. } => write!(
                f,
                "one of the inputs lacked value information (witness_utxo or non_witness_utxo)"
            ),
            SendingTooMuch { .. } => write!(
                f,
                "transaction would be invalid due to output value being greater than input value."
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

impl From<Infallible> for IndexOutOfBoundsError {
    fn from(never: Infallible) -> Self { match never {} }
}

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

/// Checks that unsigned transaction does not have scriptSig's or witness data.
// FIXME: Use of general error is horrible.
fn unsigned_tx_checks(unsigned_tx: &Transaction) -> Result<(), Error> {
    for txin in &unsigned_tx.input {
        if !txin.script_sig.is_empty() {
            return Err(Error::UnsignedTxHasScriptSigs);
        }

        if !txin.witness.is_empty() {
            return Err(Error::UnsignedTxHasScriptWitnesses);
        }
    }

    Ok(())
}

/// PSBT deserialization failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeserializeError {
    /// Decoding failed.
    Decode(serialize::Error),
    /// Not valid for PSBT v0.
    PsbtInvalid(PsbtInvalidError),
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DeserializeError::*;

        match *self {
            Decode(ref e) => write_err!(f, "decode"; e),
            PsbtInvalid(ref e) => write_err!(f, "psbt"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DeserializeError::*;

        match *self {
            Decode(ref e) => Some(e),
            PsbtInvalid(ref e) => Some(e),
        }
    }
}

impl From<serialize::Error> for DeserializeError {
    fn from(e: serialize::Error) -> Self { Self::Decode(e) }
}

impl From<PsbtInvalidError> for DeserializeError {
    fn from(e: PsbtInvalidError) -> Self { Self::PsbtInvalid(e) }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;
    #[cfg(feature = "rand-std")]
    use secp256k1::{All, SecretKey};

    use super::*;
    use crate::locktime::absolute;
    use crate::script::{ScriptBuf, ScriptBufExt as _};
    use crate::transaction::{self, OutPoint, TxIn};
    use crate::witness::Witness;
    use crate::Sequence;

    #[track_caller]
    pub fn hex_psbt(s: &str) -> Result<Psbt, crate::psbt::DeserializeError> {
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
            version: Version::Zero,
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
            version: Version::Zero,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt = hex_psbt("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();
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

    #[cfg(feature = "serde")]
    #[test]
    fn serde_psbt() {
        //! Create a full PSBT value with various fields filled and make sure it can be JSONized.
        use hashes::{hash160, ripemd160, sha256, sha256d};
        use hex::test_hex_unwrap as hex;

        use crate::psbt::Input;

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
                value: Amount::from_sat_unchecked(190_303_501_938),
                script_pubkey: ScriptBuf::from_hex(
                    "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                )
                .unwrap(),
            }],
        };
        let unknown: BTreeMap<raw::Key, Vec<u8>> =
            vec![(raw::Key { type_value: 1, key_data: vec![0, 1] }, vec![3, 4, 5])]
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
            version: Version::Zero,
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
                        value: Amount::from_sat_unchecked(190_303_501_938),
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

    // https://github.com/rust-bitcoin/rust-bitcoin/issues/3628
    #[test]
    fn combine_psbt_fuzz_3628() {
        let mut psbt1 = hex_psbt(include_str!("../../tests/data/psbt_fuzz1.hex")).unwrap();
        let psbt2 = hex_psbt(include_str!("../../tests/data/psbt_fuzz2.hex")).unwrap();

        assert!(matches!(
            psbt1.combine(psbt2).unwrap_err(),
            Error::CombineInconsistentKeySources(_)
        ));
    }

    #[cfg(feature = "rand-std")]
    fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<All>) {
        use secp256k1::rand::thread_rng;

        use crate::NetworkKind;

        let secp = Secp256k1::new();

        let sk = SecretKey::new(&mut thread_rng());
        let priv_key = PrivateKey::new(sk, NetworkKind::Test);
        let pk = PublicKey::from_private_key(&secp, priv_key);

        (priv_key, pk, secp)
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn get_key_btree_map() {
        let (priv_key, pk, secp) = gen_keys();

        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        let got = key_map.get_key(&KeyRequest::Pubkey(pk), &secp).expect("failed to get key");
        assert_eq!(got.unwrap(), priv_key)
    }

    #[test]
    fn fee() {
        let output_0_val = Amount::from_sat_unchecked(99_999_699);
        let output_1_val = Amount::from_sat_unchecked(100_000_000);
        let prev_output_val = Amount::from_sat_unchecked(200_000_000);

        let t = Psbt {
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
                        ..TxIn::EMPTY_COINBASE
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
            version: Version::Zero,
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
                                ..TxIn::EMPTY_COINBASE
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: Sequence::MAX,
                                ..TxIn::EMPTY_COINBASE
                            }
                        ],
                        output: vec![
                            TxOut {
                                value: prev_output_val,
                                script_pubkey:  ScriptBuf::new()
                            },
                            TxOut {
                                value: Amount::from_sat_unchecked(190_303_501_938),
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
            (prev_output_val - (output_0_val + output_1_val)).unwrap()
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
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn sign_psbt() {
        use crate::address::script_pubkey::ScriptBufExt as _;
        use crate::bip32::{DerivationPath, Fingerprint};
        use crate::witness_version::WitnessVersion;
        use crate::WitnessProgram;

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::EMPTY_COINBASE, TxIn::EMPTY_COINBASE],
            output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new() }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let (priv_key, pk, secp) = gen_keys();

        // key_map implements `GetKey` using KeyRequest::Pubkey. A pubkey key request does not use
        // keysource so we use default `KeySource` (fingreprint and derivation path) below.
        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        // First input we can spend. See comment above on key_map for why we use defaults here.
        let txout_wpkh = TxOut {
            value: Amount::from_sat_unchecked(10),
            script_pubkey: ScriptBuf::new_p2wpkh(pk.wpubkey_hash().unwrap()),
        };
        psbt.inputs[0].witness_utxo = Some(txout_wpkh);

        let mut map = BTreeMap::new();
        map.insert(pk.inner, (Fingerprint::default(), DerivationPath::default()));
        psbt.inputs[0].bip32_derivation = map;

        // Second input is unspendable by us e.g., from another wallet that supports future upgrades.
        let unknown_prog = WitnessProgram::new(WitnessVersion::V4, &[0xaa; 34]).unwrap();
        let txout_unknown_future = TxOut {
            value: Amount::from_sat_unchecked(10),
            script_pubkey: ScriptBuf::new_witness_program(&unknown_prog),
        };
        psbt.inputs[1].witness_utxo = Some(txout_unknown_future);

        let (signing_keys, _) = psbt.sign(&key_map, &secp).unwrap_err();

        assert_eq!(signing_keys.len(), 1);
        assert_eq!(signing_keys[&0], SigningKeys::Ecdsa(vec![pk]));
    }
}
