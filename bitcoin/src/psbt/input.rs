// SPDX-License-Identifier: CC0-1.0

//! A PSBT input.

use hashes::{hash160, ripemd160, sha256, sha256d};
use secp256k1::XOnlyPublicKey;

use super::{map, raw};
use crate::bip32::KeySource;
use crate::crypto::key::PublicKey;
use crate::crypto::{ecdsa, taproot};
use crate::prelude::{BTreeMap, Vec};
use crate::psbt::PsbtSighashType;
use crate::script::ScriptBuf;
use crate::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, NonStandardSighashTypeError, TapSighashType,
};
use crate::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use crate::transaction::{Transaction, TxOut};
use crate::witness::Witness;

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The non-witness transaction this input spends from. Should only be
    /// `Option::Some` for inputs which spend non-segwit outputs or
    /// if it is unknown whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,

    /// The transaction output this input spends from. Should only be
    /// `Option::Some` for inputs which spend segwit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-Taproot inputs.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,

    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,

    /// The redeem script for this input.
    pub redeem_script: Option<ScriptBuf>,

    /// The witness script for this input.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptBuf>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,

    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,

    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,

    /// HSAH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,

    /// HAS256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,

    /// Serialized Taproot signature with sighash type for key spend.
    pub tap_key_sig: Option<taproot::Signature>,

    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,

    /// Map of Control blocks to Script version pair.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Taproot Internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Merkle root.
    pub tap_merkle_root: Option<TapNodeHash>,

    /// Proprietary key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    /// Creates an `Input` from a serializable [`Input`].
    ///
    /// [`Input`]: crate::psbt::map::Input
    pub fn from_serializable(input: map::Input) -> Self {
        Input {
            non_witness_utxo: input.non_witness_utxo,
            witness_utxo: input.witness_utxo,
            partial_sigs: input.partial_sigs,
            sighash_type: input.sighash_type,
            redeem_script: input.redeem_script,
            witness_script: input.witness_script,
            bip32_derivation: input.bip32_derivation,
            final_script_sig: input.final_script_sig,
            final_script_witness: input.final_script_witness,
            ripemd160_preimages: input.ripemd160_preimages,
            sha256_preimages: input.sha256_preimages,
            hash160_preimages: input.hash160_preimages,
            hash256_preimages: input.hash256_preimages,
            tap_key_sig: input.tap_key_sig,
            tap_script_sigs: input.tap_script_sigs,
            tap_scripts: input.tap_scripts,
            tap_key_origins: input.tap_key_origins,
            tap_internal_key: input.tap_internal_key,
            tap_merkle_root: input.tap_merkle_root,
            proprietary: input.proprietary,
            unknown: input.unknown,
        }
    }

    /// Converts this `Input` into a serializable [`Input`].
    ///
    /// [`Input`]: crate::psbt::map::Input
    pub fn into_serializable(self) -> map::Input {
        map::Input {
            non_witness_utxo: self.non_witness_utxo,
            witness_utxo: self.witness_utxo,
            partial_sigs: self.partial_sigs,
            sighash_type: self.sighash_type,
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            final_script_sig: self.final_script_sig,
            final_script_witness: self.final_script_witness,
            ripemd160_preimages: self.ripemd160_preimages,
            sha256_preimages: self.sha256_preimages,
            hash160_preimages: self.hash160_preimages,
            hash256_preimages: self.hash256_preimages,
            tap_key_sig: self.tap_key_sig,
            tap_script_sigs: self.tap_script_sigs,
            tap_scripts: self.tap_scripts,
            tap_key_origins: self.tap_key_origins,
            tap_internal_key: self.tap_internal_key,
            tap_merkle_root: self.tap_merkle_root,
            proprietary: self.proprietary,
            unknown: self.unknown,
        }
    }

    /// Obtains the [`EcdsaSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`EcdsaSighashType::All`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a non-standard ECDSA sighash value.
    pub fn ecdsa_hash_ty(&self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.ecdsa_hash_ty())
            .unwrap_or(Ok(EcdsaSighashType::All))
    }

    /// Obtains the [`TapSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`TapSighashType::Default`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a invalid Taproot sighash value.
    pub fn taproot_hash_ty(&self) -> Result<TapSighashType, InvalidSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.taproot_hash_ty())
            .unwrap_or(Ok(TapSighashType::Default))
    }

    /// Combines this [`Input`] with `other` `Input` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        combine!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.bip32_derivation.extend(other.bip32_derivation);
        self.ripemd160_preimages.extend(other.ripemd160_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
        self.tap_script_sigs.extend(other.tap_script_sigs);
        self.tap_scripts.extend(other.tap_scripts);
        self.tap_key_origins.extend(other.tap_key_origins);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        combine!(redeem_script, self, other);
        combine!(witness_script, self, other);
        combine!(final_script_sig, self, other);
        combine!(final_script_witness, self, other);
        combine!(tap_key_sig, self, other);
        combine!(tap_internal_key, self, other);
        combine!(tap_merkle_root, self, other);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn psbt_sighash_type_ecdsa() {
        for ecdsa in &[
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*ecdsa);
            let s = format!("{}", sighash);
            let back = s.parse::<PsbtSighashType>().unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.ecdsa_hash_ty().unwrap(), *ecdsa);
        }
    }

    #[test]
    fn psbt_sighash_type_taproot() {
        for tap in &[
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*tap);
            let s = format!("{}", sighash);
            let back = s.parse::<PsbtSighashType>().unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.taproot_hash_ty().unwrap(), *tap);
        }
    }

    #[test]
    fn psbt_sighash_type_notstd() {
        let nonstd = 0xdddddddd;
        let sighash = PsbtSighashType { inner: nonstd };
        let s = format!("{}", sighash);
        let back = s.parse::<PsbtSighashType>().unwrap();

        assert_eq!(back, sighash);
        assert_eq!(back.ecdsa_hash_ty(), Err(NonStandardSighashTypeError(nonstd)));
        assert_eq!(back.taproot_hash_ty(), Err(InvalidSighashTypeError(nonstd)));
    }

    #[test]
    fn psbt_sighash_const_all() {
        assert_eq!(PsbtSighashType::ALL.to_u32(), 0x01);
        assert_eq!(PsbtSighashType::ALL.ecdsa_hash_ty().unwrap(), EcdsaSighashType::All);
        assert_eq!(PsbtSighashType::ALL.taproot_hash_ty().unwrap(), TapSighashType::All);
    }
}
