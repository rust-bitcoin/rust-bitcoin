// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use hashes::{hash160, ripemd160, sha256, sha256d};
use internals::write_err;
use secp256k1::XOnlyPublicKey;

use super::Map;
use crate::bip32::KeySource;
use crate::crypto::key::PublicKey;
use crate::crypto::{ecdsa, taproot};
use crate::locktime::absolute;
use crate::prelude::{btree_map, BTreeMap, Borrow, Box, Vec};
use crate::psbt::consts::{
    PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_HASH160, PSBT_IN_HASH256, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_PREVIOUS_TXID, PSBT_IN_PROPRIETARY, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, PSBT_IN_REQUIRED_TIME_LOCKTIME, PSBT_IN_RIPEMD160,
    PSBT_IN_SEQUENCE, PSBT_IN_SHA256, PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_SCRIPT_SIG, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO,
};
use crate::psbt::serialize::error::PsbtHash;
use crate::psbt::serialize::{raw, Error};
use crate::psbt::PsbtSighashType;
use crate::script::ScriptBuf;
use crate::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, NonStandardSighashTypeError, TapSighashType,
};
use crate::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use crate::transaction::{Transaction, TxOut, Txid};
use crate::witness::Witness;
use crate::Sequence;

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The non-witness transaction this input spends from.
    ///
    /// This should be present for inputs that spend non-segwit outputs and can be present
    /// for inputs that spend segwit outputs.
    ///
    /// PSBT_IN_NON_WITNESS_UTXO: Optional for v0, optional for v2.
    pub non_witness_utxo: Option<Transaction>,

    /// The transaction output this input spends from.
    ///
    /// This should only be present for inputs which spend segwit outputs, including
    /// P2SH embedded ones.
    ///
    /// PSBT_IN_WITNESS_UTXO: Optional for v0, optional for v2.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-Taproot inputs.
    ///
    /// PSBT_IN_PARTIAL_SIG: Optional for v0, optional for v2.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,

    /// The sighash type to be used for this input.
    ///
    /// Signatures for this input must use the sighash type, finalizers must fail to finalize inputs
    /// which have signatures that do not match the specified sighash type.
    ///
    /// PSBT_IN_SIGHASH_TYPE: Optional for v0, optional for v2.
    pub sighash_type: Option<PsbtSighashType>,

    /// The redeem script for this input if it has one.
    ///
    /// PSBT_IN_REDEEM_SCRIPT: Optional for v0, optional for v2.
    pub redeem_script: Option<ScriptBuf>,

    /// The witnessScript for this input if it has one.
    ///
    /// PSBT_IN_WITNESS_SCRIPT: Optional for v0, optional for v2.
    pub witness_script: Option<ScriptBuf>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    ///
    /// PSBT_IN_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    ///
    /// PSBT_IN_SCRIPTSIG: Optional for v0, optional for v2.
    pub final_script_sig: Option<ScriptBuf>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    ///
    /// PSBT_IN_SCRIPTWITNESS: Optional for v0, optional for v2.
    pub final_script_witness: Option<Witness>,

    /// RIPEMD160 hash to preimage map.
    ///
    /// PSBT_IN_RIPEMD160: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,

    /// SHA256 hash to preimage map.
    ///
    /// PSBT_IN_SHA256: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,

    /// HSAH160 hash to preimage map.
    ///
    /// PSBT_IN_HASH160: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,

    /// HAS256 hash to preimage map.
    ///
    /// PSBT_IN_HASH256: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,

    /// The txid of the previous transaction whose output at `self.spent_output_index` is being spent.
    ///
    /// In other words, the output being spent by this `Input` is:
    ///
    ///  `OutPoint { txid: self.previous_txid, vout: self.spent_output_index }`
    ///
    /// PSBT_IN_PREVIOUS_TXID: Excluded for v0, required for v2.
    pub previous_txid: Option<Txid>,

    /// The index of the output being spent in the transaction with the txid of `self.previous_txid`.
    ///
    /// PSBT_IN_OUTPUT_INDEX: Excluded for v0, required for v2.
    pub spent_output_index: Option<u32>,

    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number ([`Sequence::MAX`]).
    ///
    /// PSBT_IN_SEQUENCE: Excluded for v0, optional for v2.
    pub sequence: Option<Sequence>,

    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    ///
    /// PSBT_IN_REQUIRED_TIME_LOCKTIME: Excluded for v0, optional for v2.
    pub min_time: Option<absolute::Time>,

    /// The minimum block height that this input requires to be set as the transaction's lock time.
    ///
    /// PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: Excluded for v0, optional for v2.
    pub min_height: Option<absolute::Height>,

    /// Serialized Taproot signature with sighash type for key spend.
    ///
    /// PSBT_IN_TAP_SCRIPT_SIG: Optional for v0, optional for v2.
    pub tap_key_sig: Option<taproot::Signature>,

    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    ///
    /// PSBT_IN_TAP_SCRIPT_SIG: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,

    /// Map of control blocks to script version pair.
    ///
    /// PSBT_IN_TAP_LEAF_SCRIPT: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,

    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    ///
    /// PSBT_IN_TAP_BIP32_DERIVATION: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// Taproot internal key.
    ///
    /// PSBT_IN_TAP_INTERNAL_KEY: Optional for v0, optional for v2.
    pub tap_internal_key: Option<XOnlyPublicKey>,

    /// Taproot Merkle root hash.
    ///
    /// PSBT_IN_TAP_MERKLE_ROOT: Optional for v0, optional for v2.
    pub tap_merkle_root: Option<TapNodeHash>,

    /// Proprietary key-value pairs for this input.
    ///
    /// PSBT_IN_PROPRIETARY: Optional for v0, optional for v2.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    /// Checks if `Input` has fields set as required by the respective BIP.
    pub(crate) fn is_valid(&self) -> bool {
        self.assert_valid_v0().is_ok() | self.assert_valid_v2().is_ok()
    }

    /// Checks if `Input` has minimum fields required by `BIP-174`.
    pub(crate) fn assert_valid_v0(&self) -> Result<(), V0InvalidError> {
        if self.previous_txid.is_some() {
            return Err(V0InvalidError::PreviousTxid);
        }
        if self.spent_output_index.is_some() {
            return Err(V0InvalidError::SpentOutputIndex);
        }
        if self.sequence.is_some() {
            return Err(V0InvalidError::Sequence);
        }
        if self.min_time.is_some() {
            return Err(V0InvalidError::MinTime);
        }
        if self.min_height.is_some() {
            return Err(V0InvalidError::MinHeight);
        }
        Ok(())
    }

    /// Checks if `Input` has minimum fields required by `BIP-370`.
    pub(crate) fn assert_valid_v2(&self) -> Result<(), V2InvalidError> {
        if self.previous_txid.is_none() {
            return Err(V2InvalidError::PreviousTxid);
        }
        if self.spent_output_index.is_none() {
            return Err(V2InvalidError::SpentOutputIndex);
        }
        Ok(())
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

    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), Error> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            PSBT_IN_NON_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.non_witness_utxo <= <raw_key: _>|<raw_value: Transaction>
                }
            }
            PSBT_IN_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            PSBT_IN_PARTIAL_SIG => {
                impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: ecdsa::Signature>
                }
            }
            PSBT_IN_SIGHASH_TYPE => {
                impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: PsbtSighashType>
                }
            }
            PSBT_IN_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_FINAL_SCRIPTWITNESS => {
                impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Witness>
                }
            }
            PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair! {
                    &mut self.ripemd160_preimages <= raw_key|raw_value|ripemd160::Hash|PsbtHash::Ripemd
                }
            }
            PSBT_IN_SHA256 => {
                psbt_insert_hash_pair! {
                    &mut self.sha256_preimages <= raw_key|raw_value|sha256::Hash|PsbtHash::Sha256
                }
            }
            PSBT_IN_HASH160 => {
                psbt_insert_hash_pair! {
                    &mut self.hash160_preimages <= raw_key|raw_value|hash160::Hash|PsbtHash::Hash160
                }
            }
            PSBT_IN_HASH256 => {
                psbt_insert_hash_pair! {
                    &mut self.hash256_preimages <= raw_key|raw_value|sha256d::Hash|PsbtHash::Hash256
                }
            }
            PSBT_IN_PREVIOUS_TXID => {
                impl_psbt_insert_pair! {
                    self.previous_txid <= <raw_key: _>|<raw_value: Txid>
                }
            }
            PSBT_IN_OUTPUT_INDEX => {
                impl_psbt_insert_pair! {
                    self.spent_output_index <= <raw_key: _>|<raw_value: u32>
                }
            }
            PSBT_IN_SEQUENCE => {
                impl_psbt_insert_pair! {
                    self.sequence <= <raw_key: _>|< raw_value: Sequence>
                }
            }
            PSBT_IN_REQUIRED_TIME_LOCKTIME => {
                impl_psbt_insert_pair! {
                    self.min_time <= <raw_key: _>|<raw_value: absolute::Time>
                }
            }
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
                impl_psbt_insert_pair! {
                    self.min_height <= <raw_key: _>|<raw_value: absolute::Height>
                }
            }
            PSBT_IN_TAP_KEY_SIG => {
                impl_psbt_insert_pair! {
                    self.tap_key_sig <= <raw_key: _>|<raw_value: taproot::Signature>
                }
            }
            PSBT_IN_TAP_SCRIPT_SIG => {
                impl_psbt_insert_pair! {
                    self.tap_script_sigs <= <raw_key: (XOnlyPublicKey, TapLeafHash)>|<raw_value: taproot::Signature>
                }
            }
            PSBT_IN_TAP_LEAF_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.tap_scripts <= <raw_key: ControlBlock>|< raw_value: (ScriptBuf, LeafVersion)>
                }
            }
            PSBT_IN_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            PSBT_IN_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|< raw_value: XOnlyPublicKey>
                }
            }
            PSBT_IN_TAP_MERKLE_ROOT => {
                impl_psbt_insert_pair! {
                    self.tap_merkle_root <= <raw_key: _>|< raw_value: TapNodeHash>
                }
            }
            PSBT_IN_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
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

impl Map for Input {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_utxo, PSBT_IN_WITNESS_UTXO)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.partial_sigs, PSBT_IN_PARTIAL_SIG)
        }

        impl_psbt_get_pair! {
            rv.push(self.sighash_type, PSBT_IN_SIGHASH_TYPE)
        }

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_IN_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_IN_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_IN_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.ripemd160_preimages, PSBT_IN_RIPEMD160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.sha256_preimages, PSBT_IN_SHA256)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash160_preimages, PSBT_IN_HASH160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash256_preimages, PSBT_IN_HASH256)
        }

        impl_psbt_get_pair! {
            rv.push(self.previous_txid, PSBT_IN_PREVIOUS_TXID)
        }

        impl_psbt_get_pair! {
            rv.push(self.spent_output_index, PSBT_IN_OUTPUT_INDEX)
        }

        impl_psbt_get_pair! {
            rv.push(self.sequence, PSBT_IN_SEQUENCE)
        }

        impl_psbt_get_pair! {
            rv.push(self.min_time, PSBT_IN_REQUIRED_TIME_LOCKTIME)
        }

        impl_psbt_get_pair! {
            rv.push(self.min_height, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
        }
        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

impl_psbtmap_ser_de_serialize!(Input);

/// Input is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidError {
    /// Invalid for v0.
    V0Invalid(V0InvalidError),
    /// Invalid for v2.
    V2Invalid(V2InvalidError),
}

internals::impl_from_infallible!(InvalidError);

impl fmt::Display for InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => write_err!(f, "v0"; e),
            V2Invalid(ref e) => write_err!(f, "v2"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InvalidError::*;

        match *self {
            V0Invalid(ref e) => Some(e),
            V2Invalid(ref e) => Some(e),
        }
    }
}

impl From<V0InvalidError> for InvalidError {
    fn from(e: V0InvalidError) -> Self { Self::V0Invalid(e) }
}

impl From<V2InvalidError> for InvalidError {
    fn from(e: V2InvalidError) -> Self { Self::V2Invalid(e) }
}

/// Input is not valid for v0 (BIP-174).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V0InvalidError {
    /// PSBT_IN_PREVIOUS_TXID: Excluded for v0, required for v2.
    PreviousTxid,
    /// PSBT_IN_OUTPUT_INDEX: Excluded for v0, required for v2.
    SpentOutputIndex,
    /// PSBT_IN_SEQUENCE: Excluded for v0, optional for v2.
    Sequence,
    /// PSBT_IN_REQUIRED_TIME_LOCKTIME: Excluded for v0, optional for v2.
    MinTime,
    /// PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: Excluded for v0, optional for v2.
    MinHeight,
}

internals::impl_from_infallible!(V0InvalidError);

impl fmt::Display for V0InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V0InvalidError as E;

        match *self {
            E::PreviousTxid => write!(f, "PSBT_IN_PREVOUS_TXID must be excluded for v0"),
            E::SpentOutputIndex => write!(f, "PSBT_IN_OUTPUT_INDEX must be excluded for v0"),
            E::Sequence => write!(f, "PSBT_IN_SEQUENCE must be excluded for v0"),
            E::MinTime => write!(f, "PSBT_IN_REQUIRED_TIME_LOCKTIME must be excluded for v0"),
            E::MinHeight => write!(f, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME must be excluded for v0"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V0InvalidError {}

/// Input is not valid for v2 (BIP-370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2InvalidError {
    /// PSBT_IN_PREVIOUS_TXID: Excluded for v0, required for v2.
    PreviousTxid,
    /// PSBT_IN_OUTPUT_INDEX: Excluded for v0, required for v2.
    SpentOutputIndex,
}

internals::impl_from_infallible!(V2InvalidError);

impl fmt::Display for V2InvalidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use V2InvalidError as E;

        match *self {
            E::PreviousTxid => write!(f, "PSBT_IN_PREVOUS_TXID is required for v2"),
            E::SpentOutputIndex => write!(f, "PSBT_IN_OUTPUT_INDEX is required for v2"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for V2InvalidError {}

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
