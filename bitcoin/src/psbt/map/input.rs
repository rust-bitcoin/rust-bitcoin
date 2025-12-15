// SPDX-License-Identifier: CC0-1.0

use core::fmt;
use core::str::FromStr;

use hashes::{hash160, ripemd160, sha256, sha256d};

use crate::bip32::KeySource;
use crate::crypto::key::{PublicKey, XOnlyPublicKey};
use crate::crypto::{ecdsa, taproot};
use crate::prelude::{btree_map, BTreeMap, Borrow, Box, ToOwned, Vec};
use crate::psbt::map::Map;
use crate::psbt::serialize::Deserialize;
use crate::psbt::{error, raw, Error};
use crate::script::{RedeemScriptBuf, ScriptSigBuf, TapScriptBuf, WitnessScriptBuf};
use crate::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, NonStandardSighashTypeError, SighashTypeParseError,
    TapSighashType,
};
use crate::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use crate::transaction::{Transaction, TxOut};
use crate::witness::Witness;

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
const PSBT_IN_NON_WITNESS_UTXO: u64 = 0x00;
/// Type: Witness UTXO PSBT_IN_WITNESS_UTXO = 0x01
const PSBT_IN_WITNESS_UTXO: u64 = 0x01;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
const PSBT_IN_PARTIAL_SIG: u64 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
const PSBT_IN_SIGHASH_TYPE: u64 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
const PSBT_IN_REDEEM_SCRIPT: u64 = 0x04;
/// Type: Witness Script PSBT_IN_WITNESS_SCRIPT = 0x05
const PSBT_IN_WITNESS_SCRIPT: u64 = 0x05;
/// Type: BIP-0032 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
const PSBT_IN_BIP32_DERIVATION: u64 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
const PSBT_IN_FINAL_SCRIPTSIG: u64 = 0x07;
/// Type: Finalized scriptWitness PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
const PSBT_IN_FINAL_SCRIPTWITNESS: u64 = 0x08;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
const PSBT_IN_RIPEMD160: u64 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
const PSBT_IN_SHA256: u64 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
const PSBT_IN_HASH160: u64 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
const PSBT_IN_HASH256: u64 = 0x0d;
/// Type: Taproot Signature in Key Spend PSBT_IN_TAP_KEY_SIG = 0x13
const PSBT_IN_TAP_KEY_SIG: u64 = 0x13;
/// Type: Taproot Signature in Script Spend PSBT_IN_TAP_SCRIPT_SIG = 0x14
const PSBT_IN_TAP_SCRIPT_SIG: u64 = 0x14;
/// Type: Taproot Leaf Script PSBT_IN_TAP_LEAF_SCRIPT = 0x15
const PSBT_IN_TAP_LEAF_SCRIPT: u64 = 0x15;
/// Type: Taproot Key BIP-0032 Derivation Path PSBT_IN_TAP_BIP32_DERIVATION = 0x16
const PSBT_IN_TAP_BIP32_DERIVATION: u64 = 0x16;
/// Type: Taproot Internal Key PSBT_IN_TAP_INTERNAL_KEY = 0x17
const PSBT_IN_TAP_INTERNAL_KEY: u64 = 0x17;
/// Type: Taproot Merkle Root PSBT_IN_TAP_MERKLE_ROOT = 0x18
const PSBT_IN_TAP_MERKLE_ROOT: u64 = 0x18;
/// Type: MuSig2 Public Keys Participating in Aggregate Input PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a
const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u64 = 0x1a;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
const PSBT_IN_PROPRIETARY: u64 = 0xFC;

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct Input {
    /// The non-witness transaction this input spends from. Should only be
    /// `Option::Some` for inputs which spend non-SegWit outputs or
    /// if it is unknown whether an input spends a SegWit output.
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from. Should only be
    /// `Option::Some` for inputs which spend SegWit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-Taproot inputs.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<RedeemScriptBuf>,
    /// The witness script for this input.
    pub witness_script: Option<WitnessScriptBuf>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptSigBuf>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,
    /// RIPEMD160 hash to preimage map.
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map.
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HASH160 hash to preimage map.
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HASH256 hash to preimage map.
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Serialized Taproot signature with sighash type for key spend.
    pub tap_key_sig: Option<taproot::Signature>,
    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    /// Map of Control blocks to Script version pair.
    pub tap_scripts: BTreeMap<ControlBlock, (TapScriptBuf, LeafVersion)>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Taproot Internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Merkle root.
    pub tap_merkle_root: Option<TapNodeHash>,
    /// Mapping from MuSig2 aggregate keys to the participant keys from which they were aggregated.
    pub musig2_participant_pubkeys: BTreeMap<secp256k1::PublicKey, Vec<secp256k1::PublicKey>>,
    /// Proprietary key-value pairs for this input.
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

/// A Signature hash type for the corresponding input.
///
/// As of Taproot upgrade, the signature hash type can be either [`EcdsaSighashType`] or
/// [`TapSighashType`] but it is not possible to know directly which signature hash type the user is
/// dealing with. Therefore, the user is responsible for converting to/from [`PsbtSighashType`]
/// from/to the desired signature hash type they need.
///
/// # Examples
///
/// ```
/// use bitcoin::{EcdsaSighashType, TapSighashType};
/// use bitcoin::psbt::PsbtSighashType;
///
/// let _ecdsa_sighash_all: PsbtSighashType = EcdsaSighashType::All.into();
/// let _tap_sighash_all: PsbtSighashType = TapSighashType::All.into();
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PsbtSighashType {
    pub(in crate::psbt) inner: u32,
}

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.taproot_hash_ty() {
            Err(_) => write!(f, "{:#x}", self.inner),
            Ok(taproot_hash_ty) => fmt::Display::fmt(&taproot_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        //
        // NB: some of Taproot sighash types are non-standard for pre-Taproot
        // inputs. We also do not support SIGHASH_RESERVED in verbatim form
        // ("0xFF" string should be used instead).
        if let Ok(ty) = s.parse::<TapSighashType>() {
            return Ok(ty.into());
        }

        // We accept non-standard sighash values.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(Self { inner });
        }

        Err(SighashTypeParseError { unrecognized: s.to_owned() })
    }
}
impl From<EcdsaSighashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSighashType) -> Self { Self { inner: ecdsa_hash_ty as u32 } }
}

impl From<TapSighashType> for PsbtSighashType {
    fn from(taproot_hash_ty: TapSighashType) -> Self { Self { inner: taproot_hash_ty as u32 } }
}

impl PsbtSighashType {
    /// Ambiguous `ALL` sighash type, may refer to either [`EcdsaSighashType::All`]
    /// or [`TapSighashType::All`].
    ///
    /// This is equivalent to either `EcdsaSighashType::All.into()` or `TapSighashType::All.into()`.
    /// For sighash types other than `ALL` use the ECDSA or Taproot sighash type directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::{EcdsaSighashType, TapSighashType};
    /// use bitcoin::psbt::PsbtSighashType;
    /// let _ecdsa_sighash_anyone_can_pay: PsbtSighashType = EcdsaSighashType::AllPlusAnyoneCanPay.into();
    /// let _tap_sighash_anyone_can_pay: PsbtSighashType = TapSighashType::AllPlusAnyoneCanPay.into();
    /// ```
    pub const ALL: Self = Self { inner: 0x01 };

    /// Returns the [`EcdsaSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        EcdsaSighashType::from_standard(self.inner)
    }

    /// Returns the [`TapSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn taproot_hash_ty(self) -> Result<TapSighashType, InvalidSighashTypeError> {
        if self.inner > 0xffu32 {
            Err(InvalidSighashTypeError(self.inner))
        } else {
            TapSighashType::from_consensus_u8(self.inner as u8)
        }
    }

    /// Constructs a new [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag
    /// ([`EcdsaSighashType`], [`TapSighashType`] respectively).
    pub fn from_u32(n: u32) -> Self { Self { inner: n } }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 { self.inner }
}

impl Input {
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
    /// If the `sighash_type` field is set to an invalid Taproot sighash value.
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
                    self.redeem_script <= <raw_key: _>|<raw_value: RedeemScriptBuf>
                }
            }
            PSBT_IN_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: WitnessScriptBuf>
                }
            }
            PSBT_IN_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: ScriptSigBuf>
                }
            }
            PSBT_IN_FINAL_SCRIPTWITNESS => {
                impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Witness>
                }
            }
            PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair! {
                    &mut self.ripemd160_preimages <= raw_key|raw_value|ripemd160|error::PsbtHash::Ripemd
                }
            }
            PSBT_IN_SHA256 => {
                psbt_insert_hash_pair! {
                    &mut self.sha256_preimages <= raw_key|raw_value|sha256|error::PsbtHash::Sha256
                }
            }
            PSBT_IN_HASH160 => {
                psbt_insert_hash_pair! {
                    &mut self.hash160_preimages <= raw_key|raw_value|hash160|error::PsbtHash::Hash160
                }
            }
            PSBT_IN_HASH256 => {
                psbt_insert_hash_pair! {
                    &mut self.hash256_preimages <= raw_key|raw_value|sha256d|error::PsbtHash::Hash256
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
                    self.tap_scripts <= <raw_key: ControlBlock>|< raw_value: (TapScriptBuf, LeafVersion)>
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
            PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS => {
                impl_psbt_insert_pair! {
                    self.musig2_participant_pubkeys <= <raw_key: secp256k1::PublicKey>|< raw_value: Vec<secp256k1::PublicKey> >
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
        self.musig2_participant_pubkeys.extend(other.musig2_participant_pubkeys);
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

        impl_psbt_get_pair! {
            rv.push_map(self.musig2_participant_pubkeys, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)
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
