// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSBTs containing non-standard sighash types as invalid.
//!

use core::convert::TryFrom;
use core::fmt;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use hashes::Hash;
use internals::write_err;
use secp256k1::{Message, Secp256k1, Signing};

use crate::bip32::{self, KeySource, Xpriv, Xpub};
use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use crate::crypto::ecdsa;
use crate::crypto::key::{PrivateKey, PublicKey};
use crate::prelude::*;
use crate::sighash::{self, EcdsaSighashType, SighashCache};
use crate::{Amount, ScriptBuf, Sequence, Txid, Witness};

#[macro_use]
mod macros;
pub mod raw;
pub mod serialize;

mod error;
pub use self::error::Error;

mod map;
pub use self::map::{Input, Output, PsbtSighashType};

/// Future version of PSBT this library can't parse
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct FutureVersionError(u32);

impl fmt::Display for FutureVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PSBT version {} is not supported", self.0)
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for FutureVersionError {}

/// Partially signed transaction version as defined in BIP-174 and BIP-370.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[non_exhaustive]
pub enum Version {
    /// PSBT version 0, defined in BIP-174
    PsbtV0 = 0,
    /// PSBT version 2, defined in BIP-370
    PsbtV2 = 2,
}

impl Version {
    fn to_raw(self) -> u32 { self as u32 }

    fn from_raw(version: u32) -> Result<Version, FutureVersionError> {
        match version {
            v if v == Version::PsbtV0 as u32 => Ok(Version::PsbtV0),
            v if v == Version::PsbtV2 as u32 => Ok(Version::PsbtV2),
            future => Err(FutureVersionError(future)),
        }
    }
}

/// Transaction Modification flags used in PsbtV2 as described in BIP-370
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct TxModifiable {
    /// Indicates whether inputs can be added or removed
    pub input_modifiable: bool,
    /// Indicates whether outputs can be added or removed
    pub output_modifiable: bool,
    /// Indicates whether the transaction has a SIGHASH_SINGLE signature
    /// who's input and output pairing must be preserved. It essentially indicates
    /// that the Constructor must iterate the inputs to determine whether
    /// and how to add or remove an input
    pub has_sighash_single: bool,
    // More flags
}

impl TxModifiable {
    fn to_raw(self) -> u8 {
        let mut byte: u8 = 0x00;
        byte |= self.input_modifiable as u8;
        byte |= (self.output_modifiable as u8) << 1;
        byte |= (self.has_sighash_single as u8) << 2;
        byte
    }

    /// For now, there seems to be no reason to return an Error here.
    /// But since the structure is not complete yet and more flags
    /// can be introduced in future (which may or may not come with
    /// various rules for coexistence), a Result is returned here.
    fn from_raw(tx_modifiable: u8) -> Result<Self, Error> {
        Ok(TxModifiable {
            input_modifiable: tx_modifiable & 0x01 != 0,
            output_modifiable: tx_modifiable & 0x02 != 0,
            has_sighash_single: tx_modifiable & 0x04 != 0,
        })
    }

    /// Combines this TxModifiable flags with other TxModifiable flags.
    /// No reason to return an [`Error`] here, but done for probable future needs.
    fn combine(&mut self, tx_modifiable: &TxModifiable) -> Result<(), Error> {
        self.input_modifiable |= tx_modifiable.input_modifiable;
        self.output_modifiable |= tx_modifiable.output_modifiable;
        self.has_sighash_single |= tx_modifiable.has_sighash_single;
        Ok(())
    }
}

/// A Partially Signed Transaction Inner used by [`Psbt`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct PsbtInner {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Option<Transaction>,
    /// The version number of this PSBT. If omitted, the version number is PsbtV0.
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

    /// The transaction version number. Required in Psbtv2.
    pub tx_version: Option<i32>,
    /// Optional Psbtv2 field to use if no inputs specify a required locktime.
    pub fallback_locktime: Option<absolute::LockTime>,
    /// PSBTv2 field for various transaction modification flags.
    pub tx_modifiable: Option<TxModifiable>,
}

impl PsbtInner {
    /// Validates the given `PsbtInner` according to its version
    pub fn validate(&self) -> Result<(), Error> {
        match self.version {
            Version::PsbtV0 => {
                self.unsigned_tx_checks()?;

                if self.tx_version.is_some() {
                    return Err(Error::TxVersionPresent);
                }

                if self.fallback_locktime.is_some() {
                    return Err(Error::FallbackLocktimePresent);
                }

                if self.tx_modifiable.is_some() {
                    return Err(Error::TxModifiablePresent);
                }
            }
            _ => {
                if self.unsigned_tx.is_some() {
                    return Err(Error::UnsignedTxPresent);
                }

                match self.tx_version {
                    None => return Err(Error::InvalidTxVersion),
                    Some(tx_version) => {
                        // According to BIP 370, tx_version must be atleast 2
                        if tx_version < 2 {
                            return Err(Error::InvalidTxVersion);
                        }
                        return Ok(());
                    }
                }
            }
        }

        if !self.inputs.is_empty() {
            for input in &self.inputs {
                input.validate_version(self.version)?;
            }
        }
        if !self.outputs.is_empty() {
            for output in &self.outputs {
                output.validate_version(self.version)?;
            }
        }
        Ok(())
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(&self) -> Result<(), Error> {
        match self.unsigned_tx.as_ref() {
            Some(unsigned_tx) => {
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
            None => Err(Error::MustHaveUnsignedTx),
        }
    }

    /// Creates a PsbtV0 from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transaction is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error> {
        let psbt = PsbtInner {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],

            unsigned_tx: Some(tx),
            xpub: Default::default(),
            version: Version::PsbtV0,
            proprietary: Default::default(),
            unknown: Default::default(),

            tx_version: None,
            fallback_locktime: None,
            tx_modifiable: None,
        };
        psbt.unsigned_tx_checks()?;
        Ok(psbt)
    }
}

/// Partially signed transaction, commonly referred to as a PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Psbt {
    inner: PsbtInner,
}

impl TryFrom<PsbtInner> for Psbt {
    type Error = Error;

    /// Constructs a [`Psbt`] from a [`PsbtInner`].
    fn try_from(psbt: PsbtInner) -> Result<Self, Self::Error> { Psbt::new(psbt) }
}

impl Psbt {
    /// Creates a [`Psbt`] after validating `psbt` according to its version.
    pub fn new(psbt: PsbtInner) -> Result<Psbt, Error> {
        match psbt.validate() {
            Ok(()) => Ok(Psbt { inner: psbt }),
            Err(err) => Err(err),
        }
    }

    /// Returns the underlying [`PsbtInner`]
    pub fn into_inner(self) -> PsbtInner { self.inner }

    /// Returns an immutable reference to the underlying [`PsbtInner`]
    pub fn as_inner(&self) -> &PsbtInner { &self.inner }

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
    pub fn iter_funding_utxos(&self) -> Box<dyn Iterator<Item = Result<&TxOut, Error>> + '_> {
        let inner = &self.inner;
        match inner.version {
            Version::PsbtV0 => {
                let unsigned_tx = inner.unsigned_tx.as_ref().unwrap();
                assert_eq!(inner.inputs.len(), unsigned_tx.input.len());
                Box::new(unsigned_tx.input.iter().zip(&inner.inputs).map(
                    |(tx_input, psbt_input)| match (
                        &psbt_input.witness_utxo,
                        &psbt_input.non_witness_utxo,
                    ) {
                        (Some(witness_utxo), _) => Ok(witness_utxo),
                        (None, Some(non_witness_utxo)) => {
                            let vout = tx_input.previous_output.vout as usize;
                            non_witness_utxo.output.get(vout).ok_or(Error::PsbtUtxoOutOfbounds)
                        }
                        (None, None) => Err(Error::MissingUtxo),
                    },
                )) as Box<dyn Iterator<Item = Result<&TxOut, Error>>>
            }
            _ => {
                // In PsbtV2, Input contains all the details, no need of unsigned_tx
                Box::new(inner.inputs.iter().map(|input| {
                    match (&input.witness_utxo, &input.non_witness_utxo) {
                        (Some(witness_utxo), _) => Ok(witness_utxo),
                        (None, Some(non_witness_utxo)) => {
                            let output_index = input.output_index.unwrap() as usize;
                            non_witness_utxo
                                .output
                                .get(output_index)
                                .ok_or(Error::PsbtUtxoOutOfbounds)
                        }
                        (None, None) => Err(Error::MissingUtxo),
                    }
                })) as Box<dyn Iterator<Item = Result<&TxOut, Error>>>
            }
        }
    }

    /// Calculates the max lock time.
    ///
    /// Note: In case `locktime` is `None`, `new_lock` is returned. Otherwise, if `locktime`
    /// and `new_lock` are of different units, the value of `locktime` is returned.
    fn max_locktime(
        locktime: Option<absolute::LockTime>,
        new_lock: absolute::LockTime,
    ) -> absolute::LockTime {
        match locktime {
            None => new_lock,
            Some(lock) =>
                if lock.is_same_unit(new_lock) && lock < new_lock {
                    new_lock
                } else {
                    lock
                },
        }
    }

    /// Adds a new [`Input`] to this Non-PsbtV0.
    ///
    /// # Errors
    ///
    /// - [`Error::Version`] - This is a PsbtV0.
    /// - [`Error::InvalidInput`] - `input` is a PsbtV0 input.
    /// - [`Error::InputNotAddable`] when -
    ///     - Input Modification flag is `false`.
    ///     - `input` is a duplicate of an existing input.
    ///     - The given `input` does not have a compatible locktime type.
    ///     - The existing inputs don't have a compatible locktime type.
    ///     - Any of the existing inputs has a signature and the new given
    ///     `input` changes the final computed locktime.
    pub fn add_input(&mut self, input: Input) -> Result<(), Error> {
        if self.inner.version == Version::PsbtV0 {
            return Err(Error::Version("new inputs can not be added to PsbtV0"));
        }

        if self.inner.tx_modifiable.is_none()
            || !self.inner.tx_modifiable.as_ref().unwrap().input_modifiable
        {
            return Err(Error::InputNotAddable("input modifiable flag is false"));
        }
        input.validate_version(self.inner.version)?;

        let mut has_sig = false;
        let (mut max_time_locktime, mut max_height_locktime) =
            (input.required_time_locktime, input.required_height_locktime);

        for self_input in self.inner.inputs.iter() {
            // Check if this input is a duplicate of any of the existing inputs
            if self_input.previous_tx_id == input.previous_tx_id
                && self_input.output_index == input.output_index
            {
                return Err(Error::InputNotAddable("duplicate input"));
            }

            // BIP 370: If an input being added specifies a required time lock, then the
            //          Constructor must iterate through all of the existing inputs and ensure that
            //          the time lock types are compatible. Additionally, if during this iteration,
            //          it finds that any inputs have signatures, it must ensure that
            //          the newly added input does not change the transaction's locktime.
            //          If the newly added input has an incompatible time lock, then it must not be added.
            //          If it changes the transaction's locktime when there are existing signatures,
            //          it must not be added.

            // Note: At this point, it is not guaranteed that the existing inputs have compatible locktime types.
            // In case they don't, it still returns the `InputNotAddable("incompatible locktime type")` error.

            match (self_input.required_time_locktime, self_input.required_height_locktime) {
                (Some(locktime), None) => {
                    // Since this existing input doesn't support height locktime,
                    // All the other existing inputs as well as the given new input are expected
                    // to have either atleast the `required_time_locktime` specified or no locktime
                    // specified at all.
                    if max_time_locktime.is_none() && max_height_locktime.is_some() {
                        return Err(Error::InputNotAddable("incompatible locktime type"));
                    }

                    max_height_locktime = None;
                    max_time_locktime = Some(Psbt::max_locktime(max_time_locktime, locktime));
                }
                (None, Some(locktime)) => {
                    // Since this existing input doesn't support time locktime,
                    // All the other existing inputs as well as the given new input are expected
                    // to have either atleast the `required_height_locktime` specified or no locktime
                    // specified at all.
                    if max_height_locktime.is_none() && max_time_locktime.is_some() {
                        return Err(Error::InputNotAddable("incompatible locktime type"));
                    }

                    max_time_locktime = None;
                    max_height_locktime = Some(Psbt::max_locktime(max_height_locktime, locktime));
                }
                (Some(time_lock), Some(height_lock)) => {
                    if max_time_locktime.is_some() {
                        max_time_locktime = Some(Psbt::max_locktime(max_time_locktime, time_lock));
                    }

                    if max_height_locktime.is_some() {
                        max_height_locktime =
                            Some(Psbt::max_locktime(max_height_locktime, height_lock));
                    }

                    if max_time_locktime.is_none() && max_height_locktime.is_none() {
                        max_time_locktime = Some(time_lock);
                        max_height_locktime = Some(height_lock);
                    }
                }
                _ => {}
            }

            if !self_input.partial_sigs.is_empty() {
                has_sig = true;
            }
        }

        if has_sig {
            let new_locktime = match (max_time_locktime, max_height_locktime) {
                (Some(locktime), None) => locktime,
                (None, Some(locktime)) => locktime,
                // If both the lock times are present, height_lock_time must be chosen
                (Some(_), Some(locktime)) => locktime,
                _ =>
                    if let Some(locktime) = self.inner.fallback_locktime {
                        locktime
                    } else {
                        absolute::LockTime::ZERO
                    },
            };
            if self.compute_locktime()? != new_locktime {
                return Err(Error::InputNotAddable("computed locktime can not be changed"));
            }
        }

        self.inner.inputs.push(input);
        Ok(())
    }

    /// Adds a new [`Output`] to this PsbtV2.
    ///
    /// # Errors
    ///
    /// - [`Error::Version`] - This is a PsbtV0.
    /// - [`Error::OutputNotAddable`] - Output modification flag is `false`.
    /// - [`Error::InvalidOutput`] - `output` is a PsbtV0 output.
    pub fn add_output(&mut self, output: Output) -> Result<(), Error> {
        if self.inner.version == Version::PsbtV0 {
            return Err(Error::Version("New outputs can not be added to PsbtV0"));
        }
        if self.inner.tx_modifiable.is_none()
            || !self.inner.tx_modifiable.as_ref().unwrap().output_modifiable
        {
            return Err(Error::OutputNotAddable);
        }
        output.validate_version(self.inner.version)?;
        self.inner.outputs.push(output);
        Ok(())
    }

    /// Computes the locktime for a Non-PsbtV0
    ///
    /// # Errors
    ///
    /// - [`Error::RequiredLocktimeNotPresent`] if the existing inputs don't have a compatible locktime.
    fn compute_locktime(&self) -> Result<absolute::LockTime, Error> {
        let inner = &self.inner;
        let mut max_time_locktime: Option<absolute::LockTime> = None;
        let mut max_height_locktime: Option<absolute::LockTime> = None;
        let (mut time_flag, mut height_flag) = (true, true);

        for psbtin in inner.inputs.iter() {
            // See https://bips.xyz/370#determining-lock-time
            match (psbtin.required_time_locktime, psbtin.required_height_locktime) {
                (Some(lock), None) => {
                    // Not Time, but Height lock time was supposed to be present
                    if !time_flag {
                        return Err(Error::RequiredLocktimeNotPresent);
                    }
                    // Transaction can no longer contain height locktime
                    height_flag = false;
                    max_height_locktime = None;

                    max_time_locktime = Some(Psbt::max_locktime(max_time_locktime, lock));
                }
                (None, Some(lock)) => {
                    // Not Height, but Time lock time was supposed to be present
                    if !height_flag {
                        return Err(Error::RequiredLocktimeNotPresent);
                    }
                    // Transaction can no longer contain time locktime
                    time_flag = false;
                    max_time_locktime = None;

                    max_height_locktime = Some(Psbt::max_locktime(max_height_locktime, lock));
                }
                (Some(time_lock), Some(height_lock)) => {
                    if time_flag {
                        max_time_locktime = Some(Psbt::max_locktime(max_time_locktime, time_lock));
                    }

                    if height_flag {
                        max_height_locktime =
                            Some(Psbt::max_locktime(max_height_locktime, height_lock));
                    }
                }
                _ => {}
            }
        }

        match (max_time_locktime, max_height_locktime) {
            (Some(locktime), None) => Ok(locktime),
            (None, Some(locktime)) => Ok(locktime),
            // If both the lock times are present, height_lock_time must be chosen
            (Some(_), Some(locktime)) => Ok(locktime),
            _ => {
                if let Some(locktime) = inner.fallback_locktime {
                    return Ok(locktime);
                }
                Ok(absolute::LockTime::ZERO)
            }
        }
    }

    /// Generates the unique transaction ID for this [`Psbt`].
    /// See https://bips.xyz/370#unique-identification.
    ///
    /// ## Errors
    ///
    /// - [`Error::RequiredLocktimeNotPresent`] - If this is a PSBTv2 and
    /// the existing inputs don't have a compatible locktime.
    fn get_unique_id(&self) -> Result<Txid, Error> {
        let mut unsigned_tx = match self.inner.version {
            Version::PsbtV0 => self.inner.unsigned_tx.as_ref().unwrap().clone(),
            _ => self.construct_unsigned_tx()?,
        };

        // BIP 370: Since PSBT_IN_SEQUENCE can be changed by Updaters and Combiners,
        //          the sequence number in this unsigned transaction must be set to 0
        //          (not final, nor the sequence in PSBT_IN_SEQUENCE).
        for txin in unsigned_tx.input.iter_mut() {
            txin.sequence = Sequence::ZERO;
        }

        Ok(unsigned_tx.txid())
    }

    /// Constructs a new unsigned transaction from this Psbt.
    /// Should be used for Non-PsbtV0s only. Don't use this function
    /// to compare the PSBTs when PSBTv2s are involved, instead use
    /// the `Psbt::get_unique_id()` function.
    fn construct_unsigned_tx(&self) -> Result<Transaction, Error> {
        if self.inner.version == Version::PsbtV0 {
            return Ok(self.inner.unsigned_tx.as_ref().unwrap().clone());
        }
        let mut tx = Transaction {
            version: self.inner.tx_version.unwrap(),
            lock_time: self.compute_locktime()?,
            input: vec![],
            output: vec![],
        };

        for psbtin in self.inner.inputs.iter() {
            tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: psbtin.previous_tx_id.unwrap(),
                    vout: psbtin.output_index.unwrap(),
                },
                script_sig: ScriptBuf::new(),
                sequence: psbtin.sequence.unwrap_or_default(),
                witness: Witness::default(),
            });
        }

        for psbtout in self.inner.outputs.iter() {
            tx.output.push(TxOut {
                value: psbtout.amount.unwrap(),
                script_pubkey: psbtout.script.as_ref().unwrap().clone(),
            });
        }

        Ok(tx)
    }

    /// Converts this Psbt into a PsbtV0
    pub fn get_v0(self) -> Result<Self, Error> {
        match self.inner.version {
            Version::PsbtV0 => Ok(self),
            Version::PsbtV2 => {
                let tx = self.construct_unsigned_tx()?;
                let mut psbt_inner = PsbtInner {
                    unsigned_tx: Some(tx),
                    version: Version::PsbtV0,
                    tx_modifiable: None,
                    tx_version: None,
                    fallback_locktime: None,
                    ..self.inner
                };

                for input in psbt_inner.inputs.iter_mut() {
                    input.previous_tx_id = None;
                    input.output_index = None;
                    input.sequence = None;
                    input.required_time_locktime = None;
                    input.required_height_locktime = None;
                }

                for output in psbt_inner.outputs.iter_mut() {
                    output.script = None;
                    output.amount = None;
                }

                Psbt::new(psbt_inner)
            }
        }
    }

    /// Converts this Psbt into a PsbtV2
    pub fn get_v2(self) -> Result<Self, Error> {
        match self.inner.version {
            Version::PsbtV2 => Ok(self),
            Version::PsbtV0 => {
                let unsigned_tx = self.inner.unsigned_tx.unwrap();
                let mut psbt_inner = PsbtInner {
                    unsigned_tx: None,
                    version: Version::PsbtV2,
                    tx_version: Some(unsigned_tx.version),
                    fallback_locktime: Some(unsigned_tx.lock_time),
                    // No information about TxModifiable flags is available in PsbtV0
                    ..self.inner
                };

                for (input, txin) in psbt_inner.inputs.iter_mut().zip(unsigned_tx.input.into_iter())
                {
                    input.previous_tx_id = Some(txin.previous_output.txid);
                    input.output_index = Some(txin.previous_output.vout);
                    input.sequence = Some(txin.sequence);

                    // The following information is not available in PsbtV0
                    input.required_time_locktime = None;
                    input.required_height_locktime = None;
                }

                for (output, txout) in
                    psbt_inner.outputs.iter_mut().zip(unsigned_tx.output.into_iter())
                {
                    output.script = Some(txout.script_pubkey);
                    output.amount = Some(txout.value);
                }

                Psbt::new(psbt_inner)
            }
        }
    }

    /// Extracts the [`Transaction`] from a PSBT by filling in the available signature information.
    pub fn extract_tx(self) -> Result<Transaction, Error> {
        let mut tx = match self.inner.version {
            Version::PsbtV0 => self.inner.unsigned_tx.unwrap(),
            _ => self.construct_unsigned_tx()?,
        };

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inner.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
            vin.witness = psbtin.final_script_witness.unwrap_or_default();
        }

        Ok(tx)
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        let self_unsigned_txid = self.get_unique_id()?;
        let other_unsigned_txid = other.get_unique_id()?;

        if self_unsigned_txid != other_unsigned_txid {
            return Err(Error::UnexpectedUniqueId {
                expected: Box::new(self_unsigned_txid),
                actual: Box::new(other_unsigned_txid),
            });
        }

        if self.inner.version == Version::PsbtV0 && other.inner.version != Version::PsbtV0 {
            self.inner.version = other.inner.version;
            self.inner.tx_version = other.inner.tx_version;
            self.inner.fallback_locktime = other.inner.fallback_locktime;
            self.inner.tx_modifiable = other.inner.tx_modifiable;
            self.inner.unsigned_tx = None;
        } else if self.inner.version != Version::PsbtV0 && other.inner.version != Version::PsbtV0 {
            if self.inner.fallback_locktime.is_none() && other.inner.fallback_locktime.is_some() {
                self.inner.fallback_locktime = other.inner.fallback_locktime;
            }

            if other.inner.tx_modifiable.is_some() {
                match self.inner.tx_modifiable.as_mut() {
                    Some(tx_modifiable) => {
                        tx_modifiable.combine(other.inner.tx_modifiable.as_ref().unwrap())?;
                    }
                    None => {
                        self.inner.tx_modifiable = other.inner.tx_modifiable;
                    }
                }
            }
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.inner.xpub {
            match self.inner.xpub.entry(xpub) {
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

        self.inner.proprietary.extend(other.inner.proprietary);
        self.inner.unknown.extend(other.inner.unknown);

        for (self_input, other_input) in
            self.inner.inputs.iter_mut().zip(other.inner.inputs.into_iter())
        {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in
            self.inner.outputs.iter_mut().zip(other.inner.outputs.into_iter())
        {
            self_output.combine(other_output);
        }

        self.inner.validate()
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
        C: Signing,
        K: GetKey,
    {
        // Clone because we need to mutably borrow when signing.
        let tx = match self.inner.version {
            Version::PsbtV0 => self.inner.unsigned_tx.as_ref().unwrap().clone(),
            _ => self.construct_unsigned_tx().unwrap(),
        };
        let inner = &mut self.inner;
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..inner.inputs.len() {
            if let Ok(SigningAlgorithm::Ecdsa) = self.signing_algorithm(i) {
                match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                    Ok(v) => {
                        used.insert(i, v);
                    }
                    Err(e) => {
                        errors.insert(i, e);
                    }
                }
            };
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

        let input = &mut self.inner.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

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
                Ok((msg, sighash_ty)) => {
                    if self.inner.version > Version::PsbtV0 {
                        let tx_modifiable = self.inner.tx_modifiable.as_mut().unwrap();
                        if tx_modifiable.input_modifiable {
                            match sighash_ty {
                                EcdsaSighashType::AllPlusAnyoneCanPay
                                | EcdsaSighashType::NonePlusAnyoneCanPay
                                | EcdsaSighashType::SinglePlusAnyoneCanPay => {}
                                _ => {
                                    tx_modifiable.input_modifiable = false;
                                }
                            }
                        }

                        if tx_modifiable.output_modifiable {
                            match sighash_ty {
                                EcdsaSighashType::None | EcdsaSighashType::NonePlusAnyoneCanPay => {
                                }
                                _ => {
                                    tx_modifiable.output_modifiable = false;
                                }
                            }
                        }

                        if !tx_modifiable.has_sighash_single {
                            match sighash_ty {
                                EcdsaSighashType::Single
                                | EcdsaSighashType::SinglePlusAnyoneCanPay => {
                                    tx_modifiable.has_sighash_single = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    (msg, sighash_ty)
                }
            };

            let sig =
                ecdsa::Signature { sig: secp.sign_ecdsa(&msg, &sk.inner), hash_ty: sighash_ty };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

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
                let sighash = cache.legacy_signature_hash(input_index, spk, hash_ty.to_u32())?;
                // TODO: After upgrade of secp change this to Message::from_digest(sighash.to_byte_array()).
                Ok((
                    Message::from_slice(sighash.as_byte_array()).expect("sighash is 32 bytes long"),
                    hash_ty,
                ))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash =
                    cache.legacy_signature_hash(input_index, script_code, hash_ty.to_u32())?;
                // TODO: After upgrade of secp change this to Message::from_digest(sighash.to_byte_array()).
                Ok((
                    Message::from_slice(sighash.as_byte_array()).expect("sighash is 32 bytes long"),
                    hash_ty,
                ))
            }
            Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                // TODO: After upgrade of secp change this to Message::from_digest(sighash.to_byte_array()).
                Ok((
                    Message::from_slice(sighash.as_byte_array()).expect("sighash is 32 bytes long"),
                    hash_ty,
                ))
            }
            ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                // TODO: After upgrade of secp change this to Message::from_digest(sighash.to_byte_array()).
                Ok((
                    Message::from_slice(sighash.as_byte_array()).expect("sighash is 32 bytes long"),
                    hash_ty,
                ))
            }
            Wsh | ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash =
                    cache.p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)?;
                // TODO: After upgrade of secp change this to Message::from_digest(sighash.to_byte_array()).
                Ok((
                    Message::from_slice(sighash.as_byte_array()).expect("sighash is 32 bytes long"),
                    hash_ty,
                ))
            }
            Tr => {
                // This PSBT signing API is WIP, taproot to come shortly.
                Err(SignError::Unsupported)
            }
        }
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    pub fn spend_utxo(&self, input_index: usize) -> Result<&TxOut, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = if let Some(witness_utxo) = &input.witness_utxo {
            witness_utxo
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let vout = match self.inner.version {
                Version::PsbtV0 =>
                    self.inner.unsigned_tx.as_ref().unwrap().input[input_index].previous_output.vout,
                _ => self.inner.inputs[input_index].output_index.unwrap(),
            };
            &non_witness_utxo.output[vout as usize]
        } else {
            return Err(SignError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_index_is_within_bounds(input_index)?;
        Ok(&self.inner.inputs[input_index])
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the `unsigned_tx` `input` array in case of PSBTV0.
    fn check_index_is_within_bounds(
        &self,
        input_index: usize,
    ) -> Result<(), IndexOutOfBoundsError> {
        if input_index >= self.inner.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs {
                index: input_index,
                length: self.inner.inputs.len(),
            });
        }

        if self.inner.version == Version::PsbtV0
            && input_index >= self.inner.unsigned_tx.as_ref().unwrap().input.len()
        {
            return Err(IndexOutOfBoundsError::TxInput {
                index: input_index,
                length: self.inner.unsigned_tx.as_ref().unwrap().input.len(),
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
        let inner = &self.inner;
        match inner.version {
            Version::PsbtV0 =>
                for out in &inner.unsigned_tx.as_ref().unwrap().output {
                    outputs = outputs.checked_add(out.value.to_sat()).ok_or(Error::FeeOverflow)?;
                },
            _ =>
                for out in &inner.outputs {
                    outputs = outputs
                        .checked_add(out.amount.unwrap().to_sat())
                        .ok_or(Error::FeeOverflow)?;
                },
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
    /// Sighash computation error.
    SighashComputation(sighash::Error),
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::SignError::*;

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
            SighashComputation(ref e) => write!(f, "sighash: {}", e),
            UnknownOutputType => write!(f, "unable to determine the output type"),
            KeyNotFound => write!(f, "unable to find key"),
            WrongSigningAlgorithm => {
                write!(f, "attempt to sign an input with the wrong signing algorithm")
            }
            Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::SignError::*;

        match *self {
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
            SighashComputation(ref e) => Some(e),
            IndexOutOfBounds(ref e) => Some(e),
        }
    }
}

impl From<sighash::Error> for SignError {
    fn from(e: sighash::Error) -> Self { SignError::SighashComputation(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { SignError::IndexOutOfBounds(e) }
}

/// Input index out of bounds (actual index, maximum index allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
impl std::error::Error for IndexOutOfBoundsError {}

#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use base64::display::Base64Display;
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use internals::write_err;

    use super::{Error, Psbt};
    use crate::psbt::FutureVersionError;

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(Error),
        /// Future PSBT version, which is not yet supported by this library
        Version(FutureVersionError),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(::base64::DecodeError),
    }

    impl Display for PsbtParseError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Version(ref e) => write_err!(f, "unrecognized PSBT version"; e),
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
                Version(e) => Some(e),
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
    use std::collections::BTreeMap;

    use hashes::{hash160, ripemd160, sha256, Hash};
    use secp256k1::{self, Secp256k1};
    #[cfg(feature = "rand-std")]
    use secp256k1::{All, SecretKey};

    use super::*;
    use crate::bip32::{ChildNumber, KeySource, Xpriv, Xpub};
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::script::ScriptBuf;
    use crate::blockdata::transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut};
    use crate::blockdata::witness::Witness;
    use crate::internal_macros::hex;
    use crate::network::Network::Bitcoin;
    use crate::psbt::map::{Input, Output};
    use crate::psbt::raw;
    use crate::psbt::serialize::{Deserialize, Serialize};

    #[test]
    fn trivial_psbt() {
        let psbt = PsbtInner {
            unsigned_tx: Some(Transaction {
                version: 2,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            }),
            xpub: Default::default(),
            version: Version::PsbtV0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![],
            outputs: vec![],

            tx_modifiable: None,
            tx_version: None,
            fallback_locktime: None,
        };
        let psbt = Psbt::new(psbt).unwrap();
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt: Psbt = hex_psbt!("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();

        assert!(psbt.inner.inputs[0].partial_sigs.len() == 1);
        let pk = psbt.inner.inputs[0].partial_sigs.iter().next().unwrap().0;
        assert!(!pk.compressed);
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = Default::default();

        let mut sk: Xpriv = Xpriv::new_master(Bitcoin, &seed).unwrap();

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
        let expected = PsbtInner {
            unsigned_tx: Some(Transaction {
                version: 2,
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
            }),
            xpub: Default::default(),
            version: Version::PsbtV0,
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],

            tx_modifiable: None,
            tx_version: None,
            fallback_locktime: None,
        };
        let expected = Psbt::new(expected).unwrap();

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
        let psbt: Psbt = hex_psbt!(hex).unwrap();
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
            version: 1,
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
        let key_source = ("deadbeef".parse().unwrap(), "m/0'/1".parse().unwrap());
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

        let psbt = PsbtInner {
            version: Version::PsbtV0,
            xpub: {
                let xpub: Xpub =
                    "xpub661MyMwAqRbcGoRVtwfvzZsq2VBJR1LAHfQstHUoxqDorV89vRoMxUZ27kLrraAj6MPi\
                    QfrDb27gigC1VS1dBXi5jGpxmMeBXEkKkcXUTg4".parse().unwrap();
                vec![(xpub, key_source)].into_iter().collect()
            },
            unsigned_tx: Some({
                let mut unsigned = tx.clone();
                unsigned.input[0].script_sig = ScriptBuf::new();
                unsigned.input[0].witness = Witness::default();
                unsigned
            }),
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

            tx_modifiable: None,
            tx_version: None,
            fallback_locktime: None,
        };
        let psbt = Psbt::new(psbt).unwrap();
        let encoded = serde_json::to_string(&psbt).unwrap();
        let decoded: Psbt = serde_json::from_str(&encoded).unwrap();
        assert_eq!(psbt, decoded);
    }

    mod bip_vectors {
        use std::collections::BTreeMap;
        #[cfg(feature = "base64")]
        use std::str::FromStr;

        use super::*;
        use crate::blockdata::locktime::absolute;
        use crate::blockdata::script::ScriptBuf;
        use crate::blockdata::transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut};
        use crate::blockdata::witness::Witness;
        use crate::psbt::map::{Input, Map, Output};
        use crate::psbt::{raw, Error, Psbt};
        use crate::sighash::EcdsaSighashType;

        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1() {
            hex_psbt!("0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300").unwrap();
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
            hex_psbt!("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000")
                // This weird thing is necessary since rustc 0.29 prints out I/O error in a different format than later versions
                .map_err(Error::from)
                .unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2_base64() {
            use crate::psbt::PsbtParseError;
            Psbt::from_str("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==")
                // This weird thing is necessary since rustc 0.29 prints out I/O error in a different format than later versions
                .map_err(|err| match err {
                    PsbtParseError::PsbtEncoding(err) => err,
                    PsbtParseError::Version(_) => panic!("invalid version"),
                    PsbtParseError::Base64Encoding(_) => panic!("PSBT Base64 decoding failed")
                })
                .map_err(Error::from)
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3() {
            hex_psbt!("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
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
            hex_psbt!("70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000").unwrap();
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
            hex_psbt!("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key: [] })")]
        fn invalid_vector_5_base64() {
            Psbt::from_str("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA").unwrap();
        }

        #[test]
        fn valid_vector_1() {
            let unserialized = PsbtInner {
                unsigned_tx: Some(Transaction {
                    version: 2,
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
                }),
                xpub: Default::default(),
                version: Version::PsbtV0,
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),

                inputs: vec![
                    Input {
                        non_witness_utxo: Some(Transaction {
                            version: 1,
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

                tx_modifiable: None,
                tx_version: None,
                fallback_locktime: None,
            };
            let unserialized = Psbt::new(unserialized).unwrap();

            let base16str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";

            assert_eq!(unserialized.serialize_hex(), base16str);
            assert_eq!(unserialized, hex_psbt!(base16str).unwrap());

            #[cfg(feature = "base64")]
            {
                let base64str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
                assert_eq!(Psbt::from_str(base64str).unwrap(), unserialized);
                assert_eq!(base64str, unserialized.to_string());
                assert_eq!(Psbt::from_str(base64str).unwrap(), hex_psbt!(base16str).unwrap());
            }
        }

        #[test]
        fn valid_vector_2() {
            let psbt: Psbt = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();

            assert_eq!(psbt.inner.inputs.len(), 2);
            assert_eq!(psbt.inner.outputs.len(), 2);

            assert!(&psbt.inner.inputs[0].final_script_sig.is_some());

            let redeem_script = psbt.inner.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inner.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.inner.outputs {
                assert_eq!(output.get_pairs().len(), 0)
            }
        }

        #[test]
        fn valid_vector_3() {
            let psbt: Psbt = hex_psbt!("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000").unwrap();

            assert_eq!(psbt.inner.inputs.len(), 1);
            assert_eq!(psbt.inner.outputs.len(), 2);

            let tx_input = &psbt.inner.unsigned_tx.as_ref().unwrap().input[0];
            let psbt_non_witness_utxo = psbt.inner.inputs[0].non_witness_utxo.as_ref().unwrap();

            assert_eq!(tx_input.previous_output.txid, psbt_non_witness_utxo.txid());
            assert!(psbt_non_witness_utxo.output[tx_input.previous_output.vout as usize]
                .script_pubkey
                .is_p2pkh());
            assert_eq!(
                psbt.inner.inputs[0].sighash_type.as_ref().unwrap().ecdsa_hash_ty().unwrap(),
                EcdsaSighashType::All
            );
        }

        #[test]
        fn valid_vector_4() {
            let psbt: Psbt = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000").unwrap();

            assert_eq!(psbt.inner.inputs.len(), 2);
            assert_eq!(psbt.inner.outputs.len(), 2);

            assert!(&psbt.inner.inputs[0].final_script_sig.is_none());
            assert!(&psbt.inner.inputs[1].final_script_sig.is_none());

            let redeem_script = psbt.inner.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert!(redeem_script.is_p2wpkh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inner.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
            );
            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.inner.outputs {
                assert!(!output.get_pairs().is_empty())
            }
        }

        #[test]
        fn valid_vector_5() {
            let psbt: Psbt = hex_psbt!("70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000").unwrap();

            assert_eq!(psbt.inner.inputs.len(), 1);
            assert_eq!(psbt.inner.outputs.len(), 1);

            assert!(&psbt.inner.inputs[0].final_script_sig.is_none());

            let redeem_script = psbt.inner.inputs[0].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87").unwrap();

            assert!(redeem_script.is_p2wsh());
            assert_eq!(
                redeem_script.to_p2sh(),
                psbt.inner.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey
            );

            assert_eq!(redeem_script.to_p2sh(), expected_out);
        }

        #[test]
        fn valid_vector_6() {
            let psbt: Psbt = hex_psbt!("70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f0000").unwrap();

            assert_eq!(psbt.inner.inputs.len(), 1);
            assert_eq!(psbt.inner.outputs.len(), 1);

            let tx = psbt.inner.unsigned_tx.as_ref().unwrap();
            assert_eq!(
                tx.txid(),
                "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115".parse().unwrap(),
            );

            let mut unknown: BTreeMap<raw::Key, Vec<u8>> = BTreeMap::new();
            let key: raw::Key = raw::Key { type_value: 0xf0u8, key: hex!("010203040506070809") };
            let value: Vec<u8> = hex!("0102030405060708090a0b0c0d0e0f");

            unknown.insert(key, value);

            assert_eq!(psbt.inner.inputs[0].unknown, unknown)
        }
    }

    mod bip_370_vectors {
        #[cfg(feature = "base64")]
        use std::str::FromStr;

        use super::*;

        #[test]
        fn invalid_vector_1() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input and output counts are not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInputOutputCounts")]
        fn invalid_vector_1_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAH7BAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_2() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001020402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "transaction version not allowed in PsbtV0");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "TxVersionPresent")]
        fn invalid_vector_2_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAECBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_3() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001030402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "fallback locktime not allowed in PsbtV0");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "FallbackLocktimePresent")]
        fn invalid_vector_3_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEDBAIAAAAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_4() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001040102000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input and output counts are not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInputOutputCounts")]
        fn invalid_vector_4_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEEAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_5() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001050102000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input and output counts are not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInputOutputCounts")]
        fn invalid_vector_5_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEFAQIAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_6() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc68850000000001060100000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "TxModifiable not allowed in PsbtV0");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "TxModifiablePresent")]
        fn invalid_vector_6_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAEGAQAAAQBSAgAAAAHBqiVuIUuWoYIvk95Cv/O18/+NBRkwbjUV11FaXoBbEgAAAAAA/////wEYxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAAAAAAEBHxjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4BCGsCRzBEAiAFJ1pIVzTgrh87lxI3WG8OctyFgz0njA5HTNIxEsD6XgIgawSMg868PEHQuTzH2nYYXO29Aw0AWwgBi+K5i7rL33sBIQN2DcygXzmX3GWykwYPfynxUUyMUnBI4SgCsEHU/DQKJwAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_7() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc800220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_7_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gAIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA=").unwrap();
        }

        #[test]
        fn invalid_vector_8() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_8_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAQ8EAAAAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_9() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a27011004ffffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_9_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARAE/////wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_10() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a270111048c8dc46200220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_10_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonAREEjI3EYgAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_11() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a270112041027000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_11_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAAAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_12() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f00000000002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "output not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidOutput")]
        fn invalid_vector_12_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAACICA27+LCVWIZhlU7qdZcPdxkFlyhQ24FqjWkxusCRRz3ltGPadhz5UAACAAQAAgAAAAIABAAAAYgAAAAA=").unwrap();
        }

        #[test]
        fn invalid_vector_13() {
            let err = hex_psbt!("70736274ff01007102000000010b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc80000000000feffffff020008af2f00000000160014c430f64c4756da310dbd1a085572ef299926272c8bbdeb0b00000000160014a07dac8ab6ca942d379ed795f835ba71c9cc688500000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e01086b02473044022005275a485734e0ae1f3b971237586f0e72dc85833d278c0e474cd23112c0fa5e02206b048c83cebc3c41d0b93cc7da76185cedbd030d005b08018be2b98bbacbdf7b012103760dcca05f3997dc65b293060f7f29f1514c8c527048e12802b041d4fc340a2700220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000104160014a07dac8ab6ca942d379ed795f835ba71c9cc6885002202036efe2c255621986553ba9d65c3ddc64165ca1436e05aa35a4c6eb02451cf796d18f69d873e540000800100008000000080010000006200000000").unwrap_err();
            assert_eq!(err.to_string(), "output not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidOutput")]
        fn invalid_vector_13_base64() {
            Psbt::from_str("cHNidP8BAHECAAAAAQsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAAAAAAD+////AgAIry8AAAAAFgAUxDD2TEdW2jENvRoIVXLvKZkmJyyLvesLAAAAABYAFKB9rIq2ypQtN57Xlfg1unHJzGiFAAAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEIawJHMEQCIAUnWkhXNOCuHzuXEjdYbw5y3IWDPSeMDkdM0jESwPpeAiBrBIyDzrw8QdC5PMfadhhc7b0DDQBbCAGL4rmLusvfewEhA3YNzKBfOZfcZbKTBg9/KfFRTIxScEjhKAKwQdT8NAonACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEEFgAUoH2sirbKlC03nteV+DW6ccnMaIUAIgIDbv4sJVYhmGVTup1lw93GQWXKFDbgWqNaTG6wJFHPeW0Y9p2HPlQAAIABAACAAAAAgAEAAABiAAAAAA==").unwrap();
        }

        #[test]
        fn invalid_vector_14() {
            let err = hex_psbt!("70736274ff01020402000000010304000000000105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input and output counts are not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInputOutputCounts")]
        fn invalid_vector_14_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn invalid_vector_15() {
            let err = hex_psbt!("70736274ff01020402000000010304000000000104010101fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input and output counts are not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInputOutputCounts")]
        fn invalid_vector_15_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn invalid_vector_16() {
            let err = hex_psbt!("70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_16_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEPBAAAAAABEAT+////ACICAtYB+EhGpnVfd2vgDj2d6PsQrMk1+4PEX7AWLUytWreSGPadhz5UAACAAQAAgAAAAIAAAAAAKgAAAAEDCAAIry8AAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA").unwrap();
        }

        #[test]
        fn invalid_vector_17() {
            let err = hex_psbt!("70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_17_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IARAE/v///wAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn invalid_vector_18() {
            let err = hex_psbt!("70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "output not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidOutput")]
        fn invalid_vector_18_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQQWABTEMPZMR1baMQ29GghVcu8pmSYnLAAiAgLjb7/1PdU0Bwz4/TlmFGgPNXqbhdtzQL8c+nRdKtezQBj2nYc+VAAAgAEAAIAAAACAAQAAAGQAAAABAwiLvesLAAAAAAEEFgAUTdGTrJZKVqwbnhzKhFT+L0dPhRMA").unwrap();
        }

        #[test]
        fn invalid_vector_19() {
            let err = hex_psbt!("70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f0000000000220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "output not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidOutput")]
        fn invalid_vector_19_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8AIgIC1gH4SEamdV93a+AOPZ3o+xCsyTX7g8RfsBYtTK1at5IY9p2HPlQAAIABAACAAAAAgAAAAAAqAAAAAQMIAAivLwAAAAAAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn invalid_vector_20() {
            let err = hex_psbt!("70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011104ff64cd1d00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_20_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAAREE/2TNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn invalid_vector_21() {
            let err = hex_psbt!("70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f04000000000112040065cd1d00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap_err();
            assert_eq!(err.to_string(), "input not valid");
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidInput")]
        fn invalid_vector_21_base64() {
            Psbt::from_str("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEAUgIAAAABwaolbiFLlqGCL5PeQr/ztfP/jQUZMG41FddRWl6AWxIAAAAAAP////8BGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgAAAAABAR8Yxpo7AAAAABYAFLCjrxRCCEEmk8p9FmhStS2wrvBuAQ4gCwrZIUGcHIcZc11y3HOfnqngY40f5MHu8PmUQISBX8gBDwQAAAAAARIEAGXNHQAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
        }

        #[test]
        fn valid_vector_1() {
            let psbt: Psbt = hex_psbt!("70736274ff01020402000000010401010105010201fb040200000000010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_none());
            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_2() {
            let psbt: Psbt = hex_psbt!("70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_none());
            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_3() {
            let psbt: Psbt = hex_psbt!("70736274ff01020402000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff00220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_none());
            assert!(psbt.inputs[0].sequence.is_some());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_4() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001030400000000010401010105010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff0111048c8dc4620112041027000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_some());
            assert!(psbt.tx_modifiable.is_none());
            assert!(psbt.inputs[0].sequence.is_some());
            assert!(psbt.inputs[0].required_time_locktime.is_some());
            assert!(psbt.inputs[0].required_height_locktime.is_some())
        }

        #[test]
        fn valid_vector_5() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010101fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(tx_modifiable.input_modifiable);
            assert!(!tx_modifiable.output_modifiable);
            assert!(!tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_6() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010201fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(!tx_modifiable.input_modifiable);
            assert!(tx_modifiable.output_modifiable);
            assert!(!tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_7() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010401fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(!tx_modifiable.input_modifiable);
            assert!(!tx_modifiable.output_modifiable);
            assert!(tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_8() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010801fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            // Undefined tx_modifiable flags are simply ignored while decoding
            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(!tx_modifiable.input_modifiable);
            assert!(!tx_modifiable.output_modifiable);
            assert!(!tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_9() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010301fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(tx_modifiable.input_modifiable);
            assert!(tx_modifiable.output_modifiable);
            assert!(!tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_10() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010501fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(tx_modifiable.input_modifiable);
            assert!(!tx_modifiable.output_modifiable);
            assert!(tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_11() {
            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010601fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_none());
            assert!(psbt.tx_modifiable.is_some());

            let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
            assert!(!tx_modifiable.input_modifiable);
            assert!(tx_modifiable.output_modifiable);
            assert!(tx_modifiable.has_sighash_single);

            assert!(psbt.inputs[0].sequence.is_none());
            assert!(psbt.inputs[0].required_time_locktime.is_none());
            assert!(psbt.inputs[0].required_height_locktime.is_none())
        }

        #[test]
        fn valid_vector_12_13() {
            fn test_all_tx_modifiable(psbt: &PsbtInner) {
                assert_eq!(psbt.version, Version::PsbtV2);
                assert_eq!(psbt.inputs.len(), 1);
                assert_eq!(psbt.outputs.len(), 2);
                assert!(psbt.fallback_locktime.is_none());
                assert!(psbt.tx_modifiable.is_some());

                let tx_modifiable = psbt.tx_modifiable.as_ref().unwrap();
                assert!(tx_modifiable.input_modifiable);
                assert!(tx_modifiable.output_modifiable);
                assert!(tx_modifiable.has_sighash_single);

                assert!(psbt.inputs[0].sequence.is_none());
                assert!(psbt.inputs[0].required_time_locktime.is_none());
                assert!(psbt.inputs[0].required_height_locktime.is_none())
            }

            let psbt: Psbt = hex_psbt!("70736274ff0102040200000001040101010501020106010701fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt1 = psbt.inner;
            let psbt = hex_psbt!("70736274ff010204020000000104010101050102010601ff01fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f040000000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt2 = psbt.inner;

            test_all_tx_modifiable(&psbt1);
            test_all_tx_modifiable(&psbt2);
        }

        #[test]
        fn valid_vector_14() {
            let psbt: Psbt = hex_psbt!("70736274ff010204020000000103040000000001040101010501020106010701fb0402000000000100520200000001c1aa256e214b96a1822f93de42bff3b5f3ff8d0519306e3515d7515a5e805b120000000000ffffffff0118c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e0000000001011f18c69a3b00000000160014b0a3af144208412693ca7d166852b52db0aef06e010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000011004feffffff0111048c8dc4620112041027000000220202d601f84846a6755f776be00e3d9de8fb10acc935fb83c45fb0162d4cad5ab79218f69d873e540000800100008000000080000000002a0000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c00220202e36fbff53dd534070cf8fd396614680f357a9b85db7340bf1cfa745d2ad7b34018f69d873e54000080010000800000008001000000640000000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let psbt = psbt.inner;

            assert_eq!(psbt.version, Version::PsbtV2);
            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 2);
            assert!(psbt.fallback_locktime.is_some());
            assert!(psbt.tx_modifiable.is_some());
            assert!(psbt.inputs[0].sequence.is_some());
            assert!(psbt.inputs[0].required_time_locktime.is_some());
            assert!(psbt.inputs[0].required_height_locktime.is_some())
        }

        #[test]
        fn compute_locktime_1() {
            let psbt = hex_psbt!("70736274ff01020402000000010401010105010201fb040200000000010e200b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8010f0400000000000103080008af2f000000000104160014c430f64c4756da310dbd1a085572ef299926272c000103088bbdeb0b0000000001041600144dd193ac964a56ac1b9e1cca8454fe2f474f851300").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::ZERO);
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_1_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::ZERO);
        }

        #[test]
        fn compute_locktime_2() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f040100000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f0400000000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::ZERO);
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_2_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAAAAQ4gOhs7PIN9ZInqejHY5sfdUDwAG+8+BpWOdXSAjWjKeKUBDwQAAAAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::ZERO);
        }

        #[test]
        fn compute_locktime_3() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f0400000000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_3_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[test]
        fn compute_locktime_4() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f040000000001120428230000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_4_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAESBCgjAAAAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[test]
        fn compute_locktime_5() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f04000000000111048c8dc46201120428230000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_5_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[test]
        fn compute_locktime_6() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000111048b8dc4620112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f04000000000111048c8dc46201120428230000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_6_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiARIEKCMAAAABAwhPkzV3AAAAAAEEFgAUCxNSys0Dz2qht/PI1jiGcbNKXhEA").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(10000));
        }

        #[test]
        fn compute_locktime_7() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000111048b8dc46200010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f04000000000111048c8dc46201120428230000000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(1_657_048_460));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_7_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIBEgQoIwAAAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(1_657_048_460));
        }

        #[test]
        fn compute_locktime_8() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000111048b8dc4620112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f04000000000111048c8dc462000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(1_657_048_460));
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_8_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEQSLjcRiARIEECcAAAABDiA6Gzs8g31kiep6Mdjmx91QPAAb7z4GlY51dICNaMp4pQEPBAAAAAABEQSMjcRiAAEDCE+TNXcAAAAAAQQWABQLE1LKzQPPaqG388jWOIZxs0peEQA=").unwrap();
            let locktime = psbt.compute_locktime().unwrap();
            assert_eq!(locktime, absolute::LockTime::from_consensus(1_657_048_460));
        }

        #[test]
        fn compute_locktime_9() {
            let psbt = hex_psbt!("70736274ff0102040200000001030400000000010401020105010101fb040200000000010e200f758dbfbd4da7c16c8a3309c3c81e1100f561ea646db5b01752c485e1bdde9f010f04010000000112041027000000010e203a1b3b3c837d6489ea7a31d8e6c7dd503c001bef3e06958e7574808d68ca78a5010f04000000000111048c8dc462000103084f9335770000000001041600140b1352cacd03cf6aa1b7f3c8d6388671b34a5e1100").unwrap();
            let err = psbt.compute_locktime().unwrap_err();
            assert_eq!(err.to_string(), "required locktime not present in this Psbt input");
        }

        #[cfg(feature = "base64")]
        #[test]
        fn compute_locktime_9_base64() {
            let psbt = Psbt::from_str("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQIBBQEBAfsEAgAAAAABDiAPdY2/vU2nwWyKMwnDyB4RAPVh6mRttbAXUsSF4b3enwEPBAEAAAABEgQQJwAAAAEOIDobOzyDfWSJ6nox2ObH3VA8ABvvPgaVjnV0gI1oynilAQ8EAAAAAAERBIyNxGIAAQMIT5M1dwAAAAABBBYAFAsTUsrNA89qobfzyNY4hnGzSl4RAA==").unwrap();
            let err = psbt.compute_locktime().unwrap_err();
            assert_eq!(err.to_string(), "required locktime not present in this Psbt input");
        }
    }

    mod bip_371_vectors {
        use super::*;

        #[test]
        fn invalid_vectors() {
            let err = hex_psbt!("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a075701172102fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt!("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757011342173bb3d36c074afb716fec6307a069a2e450b995f3c82785945ab8df0e24260dcd703b0cbf34de399184a9481ac2b3586db6601f026a77f7e4938481bc34751701aa000000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 66"
            );
            let err = hex_psbt!("70736274ff010071020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02787c01000000000016001483a7e34bd99ff03a4962ef8a1a101bb295461ece606b042a010000001600147ac369df1b20e033d6116623957b0ac49f3c52e8000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757221602fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt!("70736274ff01007d020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02887b0100000000001600142382871c7e8421a00093f754d91281e675874b9f606b042a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000001052102fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa23200").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt!("70736274ff01007d020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff02887b0100000000001600142382871c7e8421a00093f754d91281e675874b9f606b042a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07570000220702fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da7560000800100008000000080010000000000000000").unwrap_err();
            assert_eq!(err.to_string(), "invalid xonly public key");
            let err = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6924214022cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b094089756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb0000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid hash when parsing slice");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid hash when parsing slice: invalid slice length 33 (expected 32)"
            );
            let err = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b094289756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb01010000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 66"
            );
            let err = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b093989756aa3739ccc689ec0fcf3a360be32cc0b59b16e93a1e8bb4605726b2ca7a3ff706c4176649632b2cc68e1f912b8a578e3719ce7710885c7a966f49bcd43cb0000").unwrap_err();
            #[cfg(feature = "std")]
            assert_eq!(err.to_string(), "invalid taproot signature");
            #[cfg(not(feature = "std"))]
            assert_eq!(
                err.to_string(),
                "invalid taproot signature: invalid taproot signature size: 57"
            );
            let err = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926315c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f80023202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc00000").unwrap_err();
            assert_eq!(err.to_string(), "invalid control block");
            let err = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a01000000225120030da4fce4f7db28c2cb2951631e003713856597fe963882cb500e68112cca63000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926115c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e123202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc00000").unwrap_err();
            assert_eq!(err.to_string(), "invalid control block");
        }

        fn rtt_psbt(psbt: Psbt) {
            let enc = Psbt::serialize(&psbt);
            let psbt2 = Psbt::deserialize(&enc).unwrap();
            assert_eq!(psbt, psbt2);
        }

        #[test]
        fn valid_psbt_vectors() {
            let psbt = hex_psbt!("70736274ff010052020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a01000000160014768e1eeb4cf420866033f80aceff0f9720744969000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232002202036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d818772b2da7540000800100008000000080000000000000000000").unwrap();
            let internal_key = psbt.inner.inputs[0].tap_internal_key.unwrap();
            assert!(psbt.inner.inputs[0].tap_key_origins.contains_key(&internal_key));
            rtt_psbt(psbt);

            // vector 2
            let psbt = hex_psbt!("70736274ff010052020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a01000000160014768e1eeb4cf420866033f80aceff0f9720744969000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757011340bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af342116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232002202036b772a6db74d8753c98a827958de6c78ab3312109f37d3e0304484242ece73d818772b2da7540000800100008000000080000000000000000000").unwrap();
            let internal_key = psbt.inner.inputs[0].tap_internal_key.unwrap();
            assert!(psbt.inner.inputs[0].tap_key_origins.contains_key(&internal_key));
            assert!(psbt.inner.inputs[0].tap_key_sig.is_some());
            rtt_psbt(psbt);

            // vector 3
            let psbt = hex_psbt!("70736274ff01005e020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            let internal_key = psbt.inner.outputs[0].tap_internal_key.unwrap();
            assert!(psbt.inner.outputs[0].tap_key_origins.contains_key(&internal_key));
            rtt_psbt(psbt);

            // vector 4
            let psbt = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b6926215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f823202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc04215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac097c6e6fea5ff714ff5724499990810e406e98aa10f5bf7e5f6784bc1d0a9a6ce23204320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2acc06215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f82320fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9acc021162cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d23901cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09772b2da7560000800100008002000080000000000000000021164320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b23901115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8772b2da75600008001000080010000800000000000000000211650929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2116fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca939016f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970772b2da7560000800100008003000080000000000000000001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0011820f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            assert!(psbt.inner.inputs[0].tap_internal_key.is_some());
            assert!(psbt.inner.inputs[0].tap_merkle_root.is_some());
            assert!(!psbt.inner.inputs[0].tap_key_origins.is_empty());
            assert!(!psbt.inner.inputs[0].tap_scripts.is_empty());
            rtt_psbt(psbt);

            // vector 5
            let psbt = hex_psbt!("70736274ff01005e020000000127744ababf3027fe0d6cf23a96eee2efb188ef52301954585883e69b6624b2420000000000ffffffff0148e6052a010000002251200a8cbdc86de1ce1c0f9caeb22d6df7ced3683fe423e05d1e402a879341d6f6f5000000000001012b00f2052a010000002251205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a07572116fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2321900772b2da75600008001000080000000800100000000000000011720fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa2320001052050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac001066f02c02220736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02ac02c02220631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969ac01c0222044faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273ac210744faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c42733901f06b798b92a10ed9a9d0bbfd3af173a53b1617da3a4159ca008216cd856b2e0e772b2da75600008001000080010000800000000003000000210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2107631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969390118ace409889785e0ea70ceebb8e1ca892a7a78eaede0f2e296cf435961a8f4ca772b2da756000080010000800200008000000000030000002107736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02390129a5b4915090162d759afd3fe0f93fa3326056d0b4088cb933cae7826cb8d82c772b2da7560000800100008003000080000000000300000000").unwrap();
            assert!(psbt.inner.outputs[0].tap_internal_key.is_some());
            assert!(!psbt.inner.outputs[0].tap_key_origins.is_empty());
            assert!(psbt.inner.outputs[0].tap_tree.is_some());
            rtt_psbt(psbt);

            // vector 6
            let psbt = hex_psbt!("70736274ff01005e02000000019bd48765230bf9a72e662001f972556e54f0c6f97feb56bcb5600d817f6995260100000000ffffffff0148e6052a0100000022512083698e458c6664e1595d75da2597de1e22ee97d798e706c4c0a4b5a9823cd743000000000001012b00f2052a01000000225120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b69241142cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b0940bf818d9757d6ffeb538ba057fb4c1fc4e0f5ef186e765beb564791e02af5fd3d5e2551d4e34e33d86f276b82c99c79aed3f0395a081efcd2cc2c65dd7e693d7941144320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f840e1f1ab6fabfa26b236f21833719dc1d428ab768d80f91f9988d8abef47bfb863bb1f2a529f768c15f00ce34ec283cdc07e88f8428be28f6ef64043c32911811a4114fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca96f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae97040ec1f0379206461c83342285423326708ab031f0da4a253ee45aafa5b8c92034d8b605490f8cd13e00f989989b97e215faa36f12dee3693d2daccf3781c1757f66215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac06f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f823202cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2acc04215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac097c6e6fea5ff714ff5724499990810e406e98aa10f5bf7e5f6784bc1d0a9a6ce23204320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2acc06215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f82320fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9acc021162cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d23901cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09772b2da7560000800100008002000080000000000000000021164320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b23901115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8772b2da75600008001000080010000800000000000000000211650929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005007c461e5d2116fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca939016f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970772b2da7560000800100008003000080000000000000000001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0011820f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65000105201124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e67121071124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e6711900772b2da7560000800100008000000080000000000500000000").unwrap();
            assert!(psbt.inner.inputs[0].tap_internal_key.is_some());
            assert!(psbt.inner.inputs[0].tap_merkle_root.is_some());
            assert!(!psbt.inner.inputs[0].tap_scripts.is_empty());
            assert!(!psbt.inner.inputs[0].tap_script_sigs.is_empty());
            assert!(!psbt.inner.inputs[0].tap_key_origins.is_empty());
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
        let mut unserialized = PsbtInner {
            unsigned_tx: Some(Transaction {
                version: 2,
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
            }),
            version: Version::PsbtV0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: 1,
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

            tx_modifiable: None,
            tx_version: None,
            fallback_locktime: None,
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;
        let mut unserialized = Psbt::new(unserialized).unwrap();

        let rtt: Psbt = hex_psbt!(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inner.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<Psbt, _> = hex_psbt!(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietary() {
        let mut psbt: Psbt = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.inner.proprietary.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0u8, key: b"test".to_vec() },
            b"test".to_vec(),
        );
        assert!(!psbt.inner.proprietary.is_empty());
        let rtt: Psbt = hex_psbt!(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.inner.proprietary.is_empty());
    }

    // PSBTs taken from BIP 174 test vectors.
    #[test]
    fn combine_psbts() {
        let mut psbt1 = hex_psbt!(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let psbt2 = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();
        let psbt_combined = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();

        psbt1.combine(psbt2).expect("psbt combine to succeed");
        assert_eq!(psbt1, psbt_combined);
    }

    #[test]
    fn combine_psbts_commutative() {
        let mut psbt1 = hex_psbt!(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let mut psbt2 = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();

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
        let priv_key = PrivateKey::new(sk, crate::Network::Regtest);
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

        let t = PsbtInner {
            unsigned_tx: Some(Transaction {
                version: 2,
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
            }),
            xpub: Default::default(),
            version: Version::PsbtV0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    non_witness_utxo: Some(Transaction {
                        version: 1,
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

            tx_modifiable: None,
            tx_version: None,
            fallback_locktime: None,
        };
        let mut t = Psbt::new(t).unwrap();
        assert_eq!(
            t.fee().expect("fee calculation"),
            prev_output_val - (output_0_val + output_1_val)
        );
        // no previous output
        let mut t2 = t.clone();
        t2.inner.inputs[0].non_witness_utxo = None;
        match t2.fee().unwrap_err() {
            Error::MissingUtxo => {}
            e => panic!("unexpected error: {:?}", e),
        }
        //  negative fee
        let mut t3 = t.clone();
        t3.inner.unsigned_tx.as_mut().unwrap().output[0].value = prev_output_val;
        match t3.fee().unwrap_err() {
            Error::NegativeFee => {}
            e => panic!("unexpected error: {:?}", e),
        }
        // overflow
        let unsigned_tx = t.inner.unsigned_tx.as_mut().unwrap();
        unsigned_tx.output[0].value = Amount::MAX;
        unsigned_tx.output[1].value = Amount::MAX;
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
            version: 2,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let psbt = PsbtInner::from_unsigned_tx(unsigned_tx).unwrap();
        let mut psbt = Psbt::new(psbt).unwrap();

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
        psbt.inner.inputs[0].witness_utxo = Some(txout_wpkh);

        let mut map = BTreeMap::new();
        map.insert(pk.inner, (Fingerprint::default(), DerivationPath::default()));
        psbt.inner.inputs[0].bip32_derivation = map;

        // Second input is unspendable by us e.g., from another wallet that supports future upgrades.
        let unknown_prog = WitnessProgram::new(WitnessVersion::V4, vec![0xaa; 34]).unwrap();
        let txout_unknown_future = TxOut {
            value: Amount::from_sat(10),
            script_pubkey: ScriptBuf::new_witness_program(&unknown_prog),
        };
        psbt.inner.inputs[1].witness_utxo = Some(txout_unknown_future);

        let sigs = psbt.sign(&key_map, &secp).unwrap();

        assert!(sigs.len() == 1);
        assert!(sigs[&0] == vec![pk]);
    }
}
