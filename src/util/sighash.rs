// SPDX-License-Identifier: CC0-1.0

//! Generalized, efficient, signature hash implementation.
//!
//! Implementation of the algorithm to compute the message to be signed according to
//! [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy (before Bip143).
//!

use crate::blockdata::transaction::EncodeSigningDataResult;
use crate::prelude::*;

pub use crate::blockdata::transaction::{EcdsaSighashType, SighashTypeParseError};
use crate::blockdata::witness::Witness;
use crate::consensus::{encode, Encodable};
use core::{str, fmt};
use core::ops::{Deref, DerefMut};
use core::borrow::Borrow;
use crate::hashes::{sha256, sha256d, Hash};
use crate::io;
use crate::util::taproot::{TapLeafHash, TAPROOT_ANNEX_PREFIX, TapSighashHash};
use crate::Sighash;
use crate::{Script, Transaction, TxOut};
use crate::internal_macros::serde_string_impl;

use super::taproot::LeafVersion;

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

/// Efficiently calculates signature hash message for legacy, segwit and taproot inputs.
#[derive(Debug)]
pub struct SighashCache<T: Deref<Target=Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Deref<Target=Transaction>` allows us to use borrowed and mutable borrowed types,
    /// the latter in particular is necessary for [`SighashCache::witness_mut`].
    tx: T,

    /// Common cache for taproot and segwit inputs, `None` for legacy inputs.
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs (the result of another round of sha256 on `common_cache`).
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs.
    taproot_cache: Option<TaprootCache>,
}

/// Common values cached between segwit and taproot inputs.
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and `SIGHASH_SINGLE` do not
    /// need it, but since `SIGHASH_ALL` is by far the most used variant we don't bother.
    outputs: sha256::Hash,
}

/// Values cached for segwit inputs, equivalent to [`CommonCache`] plus another round of `sha256`.
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// Values cached for taproot inputs.
#[derive(Debug)]
struct TaprootCache {
    amounts: sha256::Hash,
    script_pubkeys: sha256::Hash,
}

/// Contains outputs of previous transactions. In the case [`SchnorrSighashType`] variant is
/// `SIGHASH_ANYONECANPAY`, [`Prevouts::One`] may be used.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prevouts<'u, T> where T: 'u + Borrow<TxOut> {
    /// `One` variant allows provision of the single prevout needed. It's useful, for example, when
    /// modifier `SIGHASH_ANYONECANPAY` is provided, only prevout of the current input is needed.
    /// The first `usize` argument is the input index this [`TxOut`] is referring to.
    One(usize, T),
    /// When `SIGHASH_ANYONECANPAY` is not provided, or when the caller is giving all prevouts so
    /// the same variable can be used for multiple inputs.
    All(&'u [T]),
}

const KEY_VERSION_0: u8 = 0u8;

/// Information related to the script path spending.
///
/// This can be hashed into a [`TapLeafHash`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ScriptPath<'s> {
    script: &'s Script,
    leaf_version: LeafVersion,
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
/// Fixed values so they can be cast as integer types for encoding.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSighashType {
    /// 0x0: Used when not explicitly specified, defaults to [`SchnorrSighashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
serde_string_impl!(SchnorrSighashType, "a SchnorrSighashType data");

impl fmt::Display for SchnorrSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SchnorrSighashType::Default => "SIGHASH_DEFAULT",
            SchnorrSighashType::All => "SIGHASH_ALL",
            SchnorrSighashType::None => "SIGHASH_NONE",
            SchnorrSighashType::Single => "SIGHASH_SINGLE",
            SchnorrSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            SchnorrSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SchnorrSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for SchnorrSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_DEFAULT" => Ok(SchnorrSighashType::Default),
            "SIGHASH_ALL" => Ok(SchnorrSighashType::All),
            "SIGHASH_NONE" => Ok(SchnorrSighashType::None),
            "SIGHASH_SINGLE" => Ok(SchnorrSighashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError{ unrecognized: s.to_owned() }),
        }
    }
}

/// Possible errors in computing the signature message.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Could happen only by using `*_encode_signing_*` methods with custom writers, engines writers
    /// like the ones used in methods `*_signature_hash` do not error.
    Io(io::ErrorKind),

    /// Requested index is greater or equal than the number of inputs in the transaction.
    IndexOutOfInputsBounds {
        /// Requested index.
        index: usize,
        /// Number of transaction inputs.
        inputs_size: usize,
    },

    /// Using `SIGHASH_SINGLE` without a "corresponding output" (an output with the same index as
    /// the input being verified) is a validation failure.
    SingleWithoutCorrespondingOutput {
        /// Requested index.
        index: usize,
        /// Number of transaction outputs.
        outputs_size: usize,
    },

    /// There are mismatches in the number of prevouts provided compared to the number of inputs in
    /// the transaction.
    PrevoutsSize,

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [`Prevouts::One`] with different index.
    PrevoutIndex,

    /// A single prevout has been provided but all prevouts are needed unless using
    /// `SIGHASH_ANYONECANPAY`.
    PrevoutKind,

    /// Annex must be at least one byte long and the first bytes must be `0x50`.
    WrongAnnex,

    /// Invalid Sighash type.
    InvalidSighashType(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error_kind) => write!(f, "writer errored: {:?}", error_kind),
            Error::IndexOutOfInputsBounds { index, inputs_size } => write!(f, "Requested index ({}) is greater or equal than the number of transaction inputs ({})", index, inputs_size),
            Error::SingleWithoutCorrespondingOutput { index, outputs_size } => write!(f, "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})", index, outputs_size),
            Error::PrevoutsSize => write!(f, "Number of supplied prevouts differs from the number of inputs in transaction"),
            Error::PrevoutIndex => write!(f, "The index requested is greater than available prevouts or different from the provided [Provided::Anyone] index"),
            Error::PrevoutKind => write!(f, "A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`"),
            Error::WrongAnnex => write!(f, "Annex must be at least one byte long and the first bytes must be `0x50`"),
            Error::InvalidSighashType(hash_ty) => write!(f, "Invalid schnorr Signature hash type : {} ", hash_ty),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Io(_)
            | IndexOutOfInputsBounds { .. }
            | SingleWithoutCorrespondingOutput { .. }
            | PrevoutsSize
            | PrevoutIndex
            | PrevoutKind
            | WrongAnnex
            | InvalidSighashType(_) => None,
        }
    }
}

impl<'u, T> Prevouts<'u, T> where T: Borrow<TxOut> {
    fn check_all(&self, tx: &Transaction) -> Result<(), Error> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(Error::PrevoutsSize);
            }
        }
        Ok(())
    }

    fn get_all(&self) -> Result<&[T], Error> {
        match self {
            Prevouts::All(prevouts) => Ok(*prevouts),
            _ => Err(Error::PrevoutKind),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, Error> {
        match self {
            Prevouts::One(index, prevout) => {
                if input_index == *index {
                    Ok(prevout.borrow())
                } else {
                    Err(Error::PrevoutIndex)
                }
            }
            Prevouts::All(prevouts) => prevouts
                .get(input_index)
                .map(|x| x.borrow())
                .ok_or(Error::PrevoutIndex),
        }
    }
}

impl<'s> ScriptPath<'s> {
    /// Creates a new `ScriptPath` structure.
    pub fn new(script: &'s Script, leaf_version: LeafVersion) -> Self {
        ScriptPath {
            script,
            leaf_version,
        }
    }
    /// Creates a new `ScriptPath` structure using default leaf version value.
    pub fn with_defaults(script: &'s Script) -> Self {
        Self::new(script, LeafVersion::TapScript)
    }
    /// Computes the leaf hash for this `ScriptPath`.
    pub fn leaf_hash(&self) -> TapLeafHash {
        let mut enc = TapLeafHash::engine();

        self.leaf_version.to_consensus().consensus_encode(&mut enc).expect("Writing to hash enging should never fail");
        self.script.consensus_encode(&mut enc).expect("Writing to hash enging should never fail");

        TapLeafHash::from_engine(enc)
    }
}

impl<'s> From<ScriptPath<'s>> for TapLeafHash {
    fn from(script_path: ScriptPath<'s>) -> TapLeafHash {
        script_path.leaf_hash()
    }
}

impl From<EcdsaSighashType> for SchnorrSighashType {
    fn from(s: EcdsaSighashType) -> Self {
        match s {
            EcdsaSighashType::All => SchnorrSighashType::All,
            EcdsaSighashType::None => SchnorrSighashType::None,
            EcdsaSighashType::Single => SchnorrSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay => SchnorrSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay => SchnorrSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay => SchnorrSighashType::SinglePlusAnyoneCanPay,
        }
    }
}

impl SchnorrSighashType {
    /// Breaks the sighash flag into the "real" sighash flag and the `SIGHASH_ANYONECANPAY` boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (SchnorrSighashType, bool) {
        match self {
            SchnorrSighashType::Default => (SchnorrSighashType::Default, false),
            SchnorrSighashType::All => (SchnorrSighashType::All, false),
            SchnorrSighashType::None => (SchnorrSighashType::None, false),
            SchnorrSighashType::Single => (SchnorrSighashType::Single, false),
            SchnorrSighashType::AllPlusAnyoneCanPay => (SchnorrSighashType::All, true),
            SchnorrSighashType::NonePlusAnyoneCanPay => (SchnorrSighashType::None, true),
            SchnorrSighashType::SinglePlusAnyoneCanPay => (SchnorrSighashType::Single, true),
        }
    }

    /// Creates a [`SchnorrSighashType`] from raw `u8`.
    #[deprecated(since = "0.29.0", note = "use from_consensus_u8 instead")]
    pub fn from_u8(hash_ty: u8) -> Result<Self, Error> {
        Self::from_consensus_u8(hash_ty)
    }

    /// Constructs a [`SchnorrSighashType`] from a raw `u8`.
    pub fn from_consensus_u8(hash_ty: u8) -> Result<Self, Error> {
    use SchnorrSighashType::*;

        Ok(match hash_ty {
            0x00 => Default,
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            x => return Err(Error::InvalidSighashType(x as u32)),
        })
    }
}

impl<R: Deref<Target = Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// The sighash components are computed in a lazy manner when required. For the generated
    /// sighashes to be valid, no fields in the transaction may change except for script_sig and
    /// witness.
    pub fn new(tx: R) -> Self {
        SighashCache {
            tx,
            common_cache: None,
            taproot_cache: None,
            segwit_cache: None,
        }
    }

    /// Encodes the BIP341 signing data for any flag type into a given object implementing a
    /// [`io::Write`] trait.
    pub fn taproot_encode_signing_data_to<Write: io::Write, T: Borrow<TxOut>>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<(), Error> {
        prevouts.check_all(&self.tx)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // epoch
        0u8.consensus_encode(&mut writer)?;

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(&mut writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.version.consensus_encode(&mut writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.lock_time.consensus_encode(&mut writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .amounts
                .consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .script_pubkeys
                .consensus_encode(&mut writer)?;
            self.common_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != SchnorrSighashType::None && sighash != SchnorrSighashType::Single {
            self.common_cache().outputs.consensus_encode(&mut writer)?;
        }

        // * Data about this input:
        // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0
        // if no annex is present, or 1 otherwise
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      amount (8): value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin =
                &self
                    .tx
                    .input
                    .get(input_index)
                    .ok_or(Error::IndexOutOfInputsBounds {
                        index: input_index,
                        inputs_size: self.tx.input.len(),
                    })?;
            let previous_output = prevouts.get(input_index)?;
            txin.previous_output.consensus_encode(&mut writer)?;
            previous_output.value.consensus_encode(&mut writer)?;
            previous_output
                .script_pubkey
                .consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        } else {
            (input_index as u32).consensus_encode(&mut writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        if sighash == SchnorrSighashType::Single {
            let mut enc = sha256::Hash::engine();
            self.tx
                .output
                .get(input_index)
                .ok_or(Error::SingleWithoutCorrespondingOutput {
                    index: input_index,
                    outputs_size: self.tx.output.len(),
                })?
                .consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.into_inner().consensus_encode(&mut writer)?;
            KEY_VERSION_0.consensus_encode(&mut writer)?;
            code_separator_pos.consensus_encode(&mut writer)?;
        }

        Ok(())
    }

    /// Computes the BIP341 sighash for any flag type.
    pub fn taproot_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Computes the BIP341 sighash for a key spend.
    pub fn taproot_key_spend_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            None,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Computes the BIP341 sighash for a script spend.
    ///
    /// Assumes the default `OP_CODESEPARATOR` position of `0xFFFFFFFF`. Custom values can be
    /// provided through the more fine-grained API of [`SighashCache::taproot_encode_signing_data_to`].
    pub fn taproot_script_spend_signature_hash<S: Into<TapLeafHash>, T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        leaf_hash: S,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Encodes the BIP143 signing data for any flag type into a given object implementing a
    /// [`std::io::Write`] trait.
    pub fn segwit_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), Error> {
        let zero_hash = sha256d::Hash::all_zeros();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            self.segwit_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        {
            let txin =
                &self
                    .tx
                    .input
                    .get(input_index)
                    .ok_or(Error::IndexOutOfInputsBounds {
                        index: input_index,
                        inputs_size: self.tx.input.len(),
                    })?;

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if sighash == EcdsaSighashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = Sighash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            Sighash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.to_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Computes the BIP143 sighash for any flag type.
    pub fn segwit_signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<Sighash, Error> {
        let mut enc = Sighash::engine();
        self.segwit_encode_signing_data_to(
            &mut enc,
            input_index,
            script_code,
            value,
            sighash_type,
        )?;
        Ok(Sighash::from_engine(enc))
    }

    /// Encodes the legacy signing data for any flag type into a given object implementing a
    /// [`std::io::Write`] trait. Internally calls [`Transaction::encode_signing_data_to`].
    pub fn legacy_encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        mut writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> EncodeSigningDataResult<Error> {
        if input_index >= self.tx.input.len() {
            return EncodeSigningDataResult::WriteResult(Err(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: self.tx.input.len(),
            }));
        }

        self.tx
            .encode_signing_data_to(&mut writer, input_index, script_pubkey, sighash_type.into())
            .map_err(|e| e.into())
    }

    /// Computes the legacy sighash for any `sighash_type`.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<Sighash, Error> {
        let mut enc = Sighash::engine();
        if self.legacy_encode_signing_data_to(&mut enc, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()? {
            Ok(Sighash::from_inner(UINT256_ONE))
        } else {
            Ok(Sighash::from_engine(enc))
        }
    }

    #[inline]
    fn common_cache(&mut self) -> &CommonCache {
        Self::common_cache_minimal_borrow(&mut self.common_cache, &self.tx)
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &R,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256::Hash::from_engine(enc)
                },
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = &mut self.common_cache;
        let tx = &self.tx;
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.prevouts).into_inner(),
                ),
                sequences: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.sequences).into_inner(),
                ),
                outputs: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.outputs).into_inner(),
                ),
            }
        })
    }

    fn taproot_cache<T: Borrow<TxOut>>(&mut self, prevouts: &[T]) -> &TaprootCache
    {
        self.taproot_cache.get_or_insert_with(|| {
            let mut enc_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.borrow().value.consensus_encode(&mut enc_amounts).unwrap();
                prevout
                    .borrow()
                    .script_pubkey
                    .consensus_encode(&mut enc_script_pubkeys)
                    .unwrap();
            }
            TaprootCache {
                amounts: sha256::Hash::from_engine(enc_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
            }
        })
    }
}

impl<R: DerefMut<Target=Transaction>> SighashCache<R> {
    /// When the `SighashCache` is initialized with a mutable reference to a transaction instead of
    /// a regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    /// ```
    /// use bitcoin::blockdata::transaction::{Transaction, EcdsaSighashType};
    /// use bitcoin::util::sighash::SighashCache;
    /// use bitcoin::{PackedLockTime, Script};
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SighashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.segwit_signature_hash(inp, &prevout_script, 42, EcdsaSighashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.witness_mut(inp).unwrap().push(&Vec::new());
    /// }
    /// ```
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.input.get_mut(input_index).map(|i| &mut i.witness)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.kind())
    }
}

/// The `Annex` struct is a slice wrapper enforcing first byte is `0x50`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`.
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, Error> {
        if annex_bytes.first() == Some(&TAPROOT_ANNEX_PREFIX) {
            Ok(Annex(annex_bytes))
        } else {
            Err(Error::WrongAnnex)
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`).
    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Encodable for Annex<'a> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self.0, w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::locktime::PackedLockTime;
    use crate::consensus::deserialize;
    use crate::hashes::hex::FromHex;
    use crate::hashes::{Hash, HashEngine};
    use crate::util::sighash::{Annex, Error, Prevouts, ScriptPath, SighashCache};
    use std::str::FromStr;
    use crate::hashes::hex::ToHex;
    use crate::util::taproot::{TapTweakHash, TapSighashHash, TapBranchHash, TapLeafHash};
    use secp256k1::{self, SecretKey, XOnlyPublicKey};
    use crate::internal_macros::{hex_hash, hex_script, hex_decode};
    extern crate serde_json;

    use crate::{Script, Transaction, TxIn, TxOut};

    #[test]
    fn test_tap_sighash_hash() {
        let bytes = Vec::from_hex("00011b96877db45ffa23b307e9f0ac87b80ef9a80b4c5f0db3fbe734422453e83cc5576f3d542c5d4898fb2b696c15d43332534a7c1d1255fda38993545882df92c3e353ff6d36fbfadc4d168452afd8467f02fe53d71714fcea5dfe2ea759bd00185c4cb02bc76d42620393ca358a1a713f4997f9fc222911890afb3fe56c6a19b202df7bffdcfad08003821294279043746631b00e2dc5e52a111e213bbfe6ef09a19428d418dab0d50000000000").unwrap();
        let expected =
            Vec::from_hex("04e808aad07a40b3767a1442fead79af6ef7e7c9316d82dec409bb31e77699b0")
                .unwrap();
        let mut enc = TapSighashHash::engine();
        enc.input(&bytes);
        let hash = TapSighashHash::from_engine(enc);
        assert_eq!(expected, hash.into_inner());
    }

    #[test]
    fn test_sighashes_keyspending() {
        // following test case has been taken from bitcoin core test framework

        test_taproot_sighash(
            "020000000164eb050a5e3da0c2a65e4786f26d753b7bc69691fabccafb11f7acef36641f1846010000003101b2b404392a22000000000017a9147f2bde86fe78bf68a0544a4f290e12f0b7e0a08c87580200000000000017a91425d11723074ecfb96a0a83c3956bfaf362ae0c908758020000000000001600147e20f938993641de67bb0cdd71682aa34c4d29ad5802000000000000160014c64984dc8761acfa99418bd6bedc79b9287d652d72000000",
            "01365724000000000023542156b39dab4f8f3508e0432cfb41fab110170acaa2d4c42539cb90a4dc7c093bc500",
            0,
            "33ca0ebfb4a945eeee9569fc0f5040221275f88690b7f8592ada88ce3bdf6703",
            SchnorrSighashType::Default, None, None, None
        );

        test_taproot_sighash(
            "0200000002fff49be59befe7566050737910f6ccdc5e749c7f8860ddc140386463d88c5ad0f3000000002cf68eb4a3d67f9d4c079249f7e4f27b8854815cb1ed13842d4fbf395f9e217fd605ee24090100000065235d9203f458520000000000160014b6d48333bb13b4c644e57c43a9a26df3a44b785e58020000000000001976a914eea9461a9e1e3f765d3af3e726162e0229fe3eb688ac58020000000000001976a9143a8869c9f2b5ea1d4ff3aeeb6a8fb2fffb1ad5fe88ac0ad7125c",
            "02591f220000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece48fb310000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece",
            1,
            "626ab955d58c9a8a600a0c580549d06dc7da4e802eb2a531f62a588e430967a8",
            SchnorrSighashType::All, None, None, None
        );

        test_taproot_sighash(
            "0200000001350005f65aa830ced2079df348e2d8c2bdb4f10e2dde6a161d8a07b40d1ad87dae000000001611d0d603d9dc0e000000000017a914459b6d7d6bbb4d8837b4bf7e9a4556f952da2f5c8758020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88ac58020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88aca71c1f4f",
            "01c4811000000000002251201bf9297d0a2968ae6693aadd0fa514717afefd218087a239afb7418e2d22e65c",
            0,
            "dfa9437f9c9a1d1f9af271f79f2f5482f287cdb0d2e03fa92c8a9b216cc6061c",
            SchnorrSighashType::AllPlusAnyoneCanPay, None, None, None
        );

        test_taproot_sighash(
            "020000000185bed1a6da2bffbd60ec681a1bfb71c5111d6395b99b3f8b2bf90167111bcb18f5010000007c83ace802ded24a00000000001600142c4698f9f7a773866879755aa78c516fb332af8e5802000000000000160014d38639dfbac4259323b98a472405db0c461b31fa61073747",
            "0144c84d0000000000225120e3f2107989c88e67296ab2faca930efa2e3a5bd3ff0904835a11c9e807458621",
            0,
            "3129de36a5d05fff97ffca31eb75fcccbbbc27b3147a7a36a9e4b45d8b625067",
            SchnorrSighashType::None, None, None, None
        );

        test_taproot_sighash(
            "eb93dbb901028c8515589dac980b6e7f8e4088b77ed866ca0d6d210a7218b6fd0f6b22dd6d7300000000eb4740a9047efc0e0000000000160014913da2128d8fcf292b3691db0e187414aa1783825802000000000000160014913da2128d8fcf292b3691db0e187414aa178382580200000000000017a9143dd27f01c6f7ef9bb9159937b17f17065ed01a0c875802000000000000160014d7630e19df70ada9905ede1722b800c0005f246641000000",
            "013fed110000000000225120eb536ae8c33580290630fc495046e998086a64f8f33b93b07967d9029b265c55",
            0,
            "2441e8b0e063a2083ee790f14f2045022f07258ddde5ee01de543c9e789d80ae",
            SchnorrSighashType::NonePlusAnyoneCanPay, None, None, None
        );

        test_taproot_sighash(
            "02000000017836b409a5fed32211407e44b971591f2032053f14701fb5b3a30c0ff382f2cc9c0100000061ac55f60288fb5600000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ac58020000000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ace4000000",
            "01efa558000000000022512007071ea3dc7e331b0687d0193d1e6d6ed10e645ef36f10ef8831d5e522ac9e80",
            0,
            "30239345177cadd0e3ea413d49803580abb6cb27971b481b7788a78d35117a88",
            SchnorrSighashType::Single, None, None, None
        );

        test_taproot_sighash(
            "0100000001aa6deae89d5e0aaca58714fc76ef6f3c8284224888089232d4e663843ed3ab3eae010000008b6657a60450cb4c0000000000160014a3d42b5413ef0c0701c4702f3cd7d4df222c147058020000000000001976a91430b4ed8723a4ee8992aa2c8814cfe5c3ad0ab9d988ac5802000000000000160014365b1166a6ed0a5e8e9dff17a6d00bbb43454bc758020000000000001976a914bc98c51a84fe7fad5dc380eb8b39586eff47241688ac4f313247",
            "0107af4e00000000002251202c36d243dfc06cb56a248e62df27ecba7417307511a81ae61aa41c597a929c69",
            0,
            "bf9c83f26c6dd16449e4921f813f551c4218e86f2ec906ca8611175b41b566df",
            SchnorrSighashType::SinglePlusAnyoneCanPay, None, None, None
        );
    }

    #[test]
    fn test_sighashes_with_annex() {
        test_taproot_sighash(
            "0200000001df8123752e8f37d132c4e9f1ff7e4f9b986ade9211267e9ebd5fd22a5e718dec6d01000000ce4023b903cb7b23000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787580200000000000017a914afd0d512a2c5c2b40e25669e9cc460303c325b8b87580200000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787f6020000",
            "01ea49260000000000225120ab5e9800806bf18cb246edcf5fe63441208fe955a4b5a35bbff65f5db622a010",
            0,
            "3b003000add359a364a156e73e02846782a59d0d95ca8c4638aaad99f2ef915c",
            SchnorrSighashType::SinglePlusAnyoneCanPay,
            Some("507b979802e62d397acb29f56743a791894b99372872fc5af06a4f6e8d242d0615cda53062bb20e6ec79756fe39183f0c128adfe85559a8fa042b042c018aa8010143799e44f0893c40e1e"),
            None,
            None,
        );
    }

    #[test]
    fn test_sighashes_with_script_path() {
        test_taproot_sighash(
            "020000000189fc651483f9296b906455dd939813bf086b1bbe7c77635e157c8e14ae29062195010000004445b5c7044561320000000000160014331414dbdada7fb578f700f38fb69995fc9b5ab958020000000000001976a914268db0a8104cc6d8afd91233cc8b3d1ace8ac3ef88ac580200000000000017a914ec00dcb368d6a693e11986d265f659d2f59e8be2875802000000000000160014c715799a49a0bae3956df9c17cb4440a673ac0df6f010000",
            "011bec34000000000022512028055142ea437db73382e991861446040b61dd2185c4891d7daf6893d79f7182",
            0,
            "d66de5274a60400c7b08c86ba6b7f198f40660079edf53aca89d2a9501317f2e",
            SchnorrSighashType::All,
            None,
            Some("20cc4e1107aea1d170c5ff5b6817e1303010049724fb3caa7941792ea9d29b3e2bacab"),
            None,
        );
    }

    #[test]
    fn test_sighashes_with_script_path_raw_hash() {
        test_taproot_sighash(
            "020000000189fc651483f9296b906455dd939813bf086b1bbe7c77635e157c8e14ae29062195010000004445b5c7044561320000000000160014331414dbdada7fb578f700f38fb69995fc9b5ab958020000000000001976a914268db0a8104cc6d8afd91233cc8b3d1ace8ac3ef88ac580200000000000017a914ec00dcb368d6a693e11986d265f659d2f59e8be2875802000000000000160014c715799a49a0bae3956df9c17cb4440a673ac0df6f010000",
            "011bec34000000000022512028055142ea437db73382e991861446040b61dd2185c4891d7daf6893d79f7182",
            0,
            "d66de5274a60400c7b08c86ba6b7f198f40660079edf53aca89d2a9501317f2e",
            SchnorrSighashType::All,
            None,
            None,
            Some("15a2530514e399f8b5cf0b3d3112cf5b289eaa3e308ba2071b58392fdc6da68a"),
        );
    }

    #[test]
    fn test_sighashes_with_annex_and_script() {
        test_taproot_sighash(
            "020000000132fb72cb8fba496755f027a9743e2d698c831fdb8304e4d1a346ac92cbf51acba50100000026bdc7df044aad34000000000017a9144fa2554ed6174586854fa3bc01de58dcf33567d0875802000000000000160014950367e1e62cdf240b35b883fc2f5e39f0eb9ab95802000000000000160014950367e1e62cdf240b35b883fc2f5e39f0eb9ab958020000000000001600141b31217d48ccc8760dcc0710fade5866d628e733a02d5122",
            "011458360000000000225120a7baec3fb9f84614e3899fcc010c638f80f13539344120e1f4d8b68a9a011a13",
            0,
            "a0042aa434f9a75904b64043f2a283f8b4c143c7f4f7f49a6cbe5b9f745f4c15",
            SchnorrSighashType::All,
            Some("50a6272b470e1460e3332ade7bb14b81671c564fb6245761bd5bd531394b28860e0b3808ab229fb51791fb6ae6fa82d915b2efb8f6df83ae1f5ab3db13e30928875e2a22b749d89358de481f19286cd4caa792ce27f9559082d227a731c5486882cc707f83da361c51b7aadd9a0cf68fe7480c410fa137b454482d9a1ebf0f96d760b4d61426fc109c6e8e99a508372c45caa7b000a41f8251305da3f206c1849985ba03f3d9592832b4053afbd23ab25d0465df0bc25a36c223aacf8e04ec736a418c72dc319e4da3e972e349713ca600965e7c665f2090d5a70e241ac164115a1f5639f28b1773327715ca307ace64a2de7f0e3df70a2ffee3857689f909c0dad46d8a20fa373a4cc6eed6d4c9806bf146f0d76baae1"),
            Some("7520ab9160dd8299dc1367659be3e8f66781fe440d52940c7f8d314a89b9f2698d406ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6eadac"),
            None,
        );
    }

    #[test]
    fn test_sighash_errors() {
        let dumb_tx = Transaction {
            version: 0,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let mut c = SighashCache::new(&dumb_tx);

        // 1.29 fixes
        let empty_vec = vec![];
        let empty_prevouts : Prevouts<TxOut> = Prevouts::All(&empty_vec);
        assert_eq!(
            c.taproot_signature_hash(0, &empty_prevouts, None, None, SchnorrSighashType::All),
            Err(Error::PrevoutsSize)
        );
        let two = vec![TxOut::default(), TxOut::default()];
        let too_many_prevouts = Prevouts::All(&two);
        assert_eq!(
            c.taproot_signature_hash(0, &too_many_prevouts, None, None, SchnorrSighashType::All),
            Err(Error::PrevoutsSize)
        );
        let tx_out = TxOut::default();
        let prevout = Prevouts::One(1, &tx_out);
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, SchnorrSighashType::All),
            Err(Error::PrevoutKind)
        );
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, SchnorrSighashType::AllPlusAnyoneCanPay),
            Err(Error::PrevoutIndex)
        );
        assert_eq!(
            c.taproot_signature_hash(10, &prevout, None, None, SchnorrSighashType::AllPlusAnyoneCanPay),
            Err(Error::IndexOutOfInputsBounds {
                index: 10,
                inputs_size: 1
            })
        );
        let prevout = Prevouts::One(0, &tx_out);
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, SchnorrSighashType::SinglePlusAnyoneCanPay),
            Err(Error::SingleWithoutCorrespondingOutput {
                index: 0,
                outputs_size: 0
            })
        );
        assert_eq!(
            c.legacy_signature_hash(10, &Script::default(), 0u32),
            Err(Error::IndexOutOfInputsBounds {
                index: 10,
                inputs_size: 1
            })
        );
    }

    #[test]
    fn test_annex_errors() {
        assert_eq!(Annex::new(&[]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&[0x51]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&[0x51, 0x50]), Err(Error::WrongAnnex));
    }

    #[allow(clippy::too_many_arguments)]
    fn test_taproot_sighash(
        tx_hex: &str,
        prevout_hex: &str,
        input_index: usize,
        expected_hash: &str,
        sighash_type: SchnorrSighashType,
        annex_hex: Option<&str>,
        script_hex: Option<&str>,
        script_leaf_hash: Option<&str>,
    ) {
        let tx_bytes = Vec::from_hex(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        let prevout_bytes = Vec::from_hex(prevout_hex).unwrap();
        let prevouts: Vec<TxOut> = deserialize(&prevout_bytes).unwrap();
        let annex_inner;
        let annex = match annex_hex {
            Some(annex_hex) => {
                annex_inner = Vec::from_hex(annex_hex).unwrap();
                Some(Annex::new(&annex_inner).unwrap())
            }
            None => None,
        };

        let leaf_hash =  match (script_hex, script_leaf_hash) {
            (Some(script_hex), _) => {
                let script_inner = Script::from_hex(script_hex).unwrap();
                Some(ScriptPath::with_defaults(&script_inner).leaf_hash())
            }
            (_, Some(script_leaf_hash)) => {
                Some(TapLeafHash::from_hex(script_leaf_hash).unwrap())
            }
            _ => None,
        };
        // All our tests use the default `0xFFFFFFFF` codeseparator value
        let leaf_hash = leaf_hash.map(|lh| (lh, 0xFFFFFFFF));

        let prevouts = if sighash_type.split_anyonecanpay_flag().1 && tx_bytes[0] % 2 == 0 {
            // for anyonecanpay the `Prevouts::All` variant is good anyway, but sometimes we want to
            // test other codepaths
            Prevouts::One(input_index, prevouts[input_index].clone())
        } else {
            Prevouts::All(&prevouts)
        };

        let mut sighash_cache = SighashCache::new(&tx);

        let hash = sighash_cache
            .taproot_signature_hash(input_index, &prevouts, annex, leaf_hash, sighash_type)
            .unwrap();
        let expected = Vec::from_hex(expected_hash).unwrap();
        assert_eq!(expected, hash.into_inner());
    }

    #[test]
    fn bip_341_sighash_tests() {

        let data = bip_341_read_json();
        assert!(data["version"].as_u64().unwrap() == 1u64);
        let secp = &secp256k1::Secp256k1::new();
        let key_path = &data["keyPathSpending"].as_array().unwrap()[0];

        let raw_unsigned_tx = hex_decode!(Transaction, key_path["given"]["rawUnsignedTx"].as_str().unwrap());
        let mut utxos = vec![];
        for utxo in key_path["given"]["utxosSpent"].as_array().unwrap() {
            let spk = hex_script!(utxo["scriptPubKey"].as_str().unwrap());
            let amt = utxo["amountSats"].as_u64().unwrap();
            utxos.push(TxOut {value: amt, script_pubkey: spk });
        }

        // Test intermediary
        let mut cache = SighashCache::new(&raw_unsigned_tx);
        let expected_amt_hash = key_path["intermediary"]["hashAmounts"].as_str().unwrap();
        let expected_outputs_hash = key_path["intermediary"]["hashOutputs"].as_str().unwrap();
        let expected_prevouts_hash = key_path["intermediary"]["hashPrevouts"].as_str().unwrap();
        let expected_spks_hash = key_path["intermediary"]["hashScriptPubkeys"].as_str().unwrap();
        let expected_sequences_hash = key_path["intermediary"]["hashSequences"].as_str().unwrap();

        // Compute all caches
        assert_eq!(expected_amt_hash, cache.taproot_cache(&utxos).amounts.to_hex());
        assert_eq!(expected_outputs_hash, cache.common_cache().outputs.to_hex());
        assert_eq!(expected_prevouts_hash, cache.common_cache().prevouts.to_hex());
        assert_eq!(expected_spks_hash, cache.taproot_cache(&utxos).script_pubkeys.to_hex());
        assert_eq!(expected_sequences_hash, cache.common_cache().sequences.to_hex());

        for inp in key_path["inputSpending"].as_array().unwrap() {
            let tx_ind = inp["given"]["txinIndex"].as_u64().unwrap() as usize;
            let internal_priv_key = hex_hash!(SecretKey, inp["given"]["internalPrivkey"].as_str().unwrap());
            let merkle_root = if inp["given"]["merkleRoot"].is_null() {
                None
            } else {
                Some(hex_hash!(TapBranchHash, inp["given"]["merkleRoot"].as_str().unwrap()))
            };
            let hash_ty = SchnorrSighashType::from_consensus_u8(inp["given"]["hashType"].as_u64().unwrap() as u8).unwrap();

            let expected_internal_pk = hex_hash!(XOnlyPublicKey, inp["intermediary"]["internalPubkey"].as_str().unwrap());
            let expected_tweak = hex_hash!(TapTweakHash, inp["intermediary"]["tweak"].as_str().unwrap());
            let expected_tweaked_priv_key = hex_hash!(SecretKey, inp["intermediary"]["tweakedPrivkey"].as_str().unwrap());
            let expected_sig_msg = Vec::<u8>::from_hex(inp["intermediary"]["sigMsg"].as_str().unwrap()).unwrap();
            let expected_sighash = hex_hash!(TapSighashHash, inp["intermediary"]["sigHash"].as_str().unwrap());
            let sig_str = inp["expected"]["witness"][0].as_str().unwrap();
            let (expected_key_spend_sig, expected_hash_ty) = if sig_str.len() == 128 {
                (secp256k1::schnorr::Signature::from_str(sig_str).unwrap(), SchnorrSighashType::Default)
            } else {
                let hash_ty = SchnorrSighashType::from_consensus_u8(Vec::<u8>::from_hex(&sig_str[128..]).unwrap()[0]).unwrap();
                (secp256k1::schnorr::Signature::from_str(&sig_str[..128]).unwrap(), hash_ty)
            };

            // tests
            let keypair = secp256k1::KeyPair::from_secret_key(secp, &internal_priv_key);
            let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
            let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak.to_scalar()).unwrap();
            let mut sig_msg = Vec::new();
            cache.taproot_encode_signing_data_to(
                &mut sig_msg,
                tx_ind,
                &Prevouts::All(&utxos),
                None,
                None,
                hash_ty
            ).unwrap();
            let sighash = cache.taproot_signature_hash(
                tx_ind,
                &Prevouts::All(&utxos),
                None,
                None,
                hash_ty
            ).unwrap();

            let msg = secp256k1::Message::from(sighash);
            let key_spend_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

            assert_eq!(expected_internal_pk, internal_key);
            assert_eq!(expected_tweak, tweak);
            assert_eq!(expected_sig_msg, sig_msg);
            assert_eq!(expected_sighash, sighash);
            assert_eq!(expected_hash_ty, hash_ty);
            assert_eq!(expected_key_spend_sig, key_spend_sig);

            let tweaked_priv_key = SecretKey::from_keypair(&tweaked_keypair);
            assert_eq!(expected_tweaked_priv_key, tweaked_priv_key);
        }
    }

    fn bip_341_read_json() -> serde_json::Value {
        let json_str = include_str!("../../test_data/bip341_tests.json");
        serde_json::from_str(json_str).expect("JSON was not well-formatted")
    }

    #[test]
    fn sighashtype_fromstr_display() {
        let sighashtypes = vec![
            ("SIGHASH_DEFAULT", SchnorrSighashType::Default),
            ("SIGHASH_ALL", SchnorrSighashType::All),
            ("SIGHASH_NONE", SchnorrSighashType::None),
            ("SIGHASH_SINGLE", SchnorrSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", SchnorrSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", SchnorrSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", SchnorrSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(SchnorrSighashType::from_str(s).unwrap(), sht);
        }
        let sht_mistakes = vec![
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "DEFAULT",
            "ALL",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(SchnorrSighashType::from_str(s).unwrap_err().to_string(), format!("Unrecognized SIGHASH string '{}'", s));
        }
    }
}
