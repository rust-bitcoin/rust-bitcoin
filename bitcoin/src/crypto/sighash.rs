// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed according to
//! [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy (before Bip143).
//!
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.

use core::{fmt, str};

use hashes::{hash_newtype, sha256, sha256d, sha256t_hash_newtype, Hash};
use internals::write_err;
use io::Write;

use crate::blockdata::witness::Witness;
use crate::consensus::{encode, Encodable};
use crate::prelude::*;
use crate::taproot::{LeafVersion, TapLeafHash, TAPROOT_ANNEX_PREFIX};
use crate::{transaction, Amount, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
#[rustfmt::skip]
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

macro_rules! impl_thirty_two_byte_hash {
    ($ty:ident) => {
        impl secp256k1::ThirtyTwoByteHash for $ty {
            fn into_32(self) -> [u8; 32] { self.to_byte_array() }
        }
    };
}

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);

    /// Hash of a transaction according to the segwit version 0 signature algorithm.
    #[hash_newtype(forward)]
    pub struct SegwitV0Sighash(sha256d::Hash);
}

impl_thirty_two_byte_hash!(LegacySighash);
impl_thirty_two_byte_hash!(SegwitV0Sighash);

sha256t_hash_newtype! {
    pub struct TapSighashTag = hash_str("TapSighash");

    /// Taproot-tagged hash with tag \"TapSighash\".
    ///
    /// This hash type is used for computing taproot signature hash."
    #[hash_newtype(forward)]
    pub struct TapSighash(_);
}

impl_thirty_two_byte_hash!(TapSighash);

/// Efficiently calculates signature hash message for legacy, segwit and taproot inputs.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Borrow<Transaction>` allows us to use borrowed and mutable borrowed types,
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

/// Contains outputs of previous transactions. In the case [`TapSighashType`] variant is
/// `SIGHASH_ANYONECANPAY`, [`Prevouts::One`] may be used.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prevouts<'u, T>
where
    T: 'u + Borrow<TxOut>,
{
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
pub enum TapSighashType {
    /// 0x0: Used when not explicitly specified, defaults to [`TapSighashType::All`]
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
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(TapSighashType, "a TapSighashType data");

impl fmt::Display for TapSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TapSighashType::*;

        let s = match self {
            Default => "SIGHASH_DEFAULT",
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for TapSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use TapSighashType::*;

        match s {
            "SIGHASH_DEFAULT" => Ok(Default),
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl<'u, T> Prevouts<'u, T>
where
    T: Borrow<TxOut>,
{
    fn check_all(&self, tx: &Transaction) -> Result<(), PrevoutsSizeError> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(PrevoutsSizeError);
            }
        }
        Ok(())
    }

    fn get_all(&self) -> Result<&[T], PrevoutsKindError> {
        match self {
            Prevouts::All(prevouts) => Ok(*prevouts),
            _ => Err(PrevoutsKindError),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, PrevoutsIndexError> {
        match self {
            Prevouts::One(index, prevout) =>
                if input_index == *index {
                    Ok(prevout.borrow())
                } else {
                    Err(PrevoutsIndexError::InvalidOneIndex)
                },
            Prevouts::All(prevouts) => prevouts
                .get(input_index)
                .map(|x| x.borrow())
                .ok_or(PrevoutsIndexError::InvalidAllIndex),
        }
    }
}

/// The number of supplied prevouts differs from the number of inputs in the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsSizeError;

impl fmt::Display for PrevoutsSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "number of supplied prevouts differs from the number of inputs in transaction")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsSizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// A single prevout was been provided but all prevouts are needed without `ANYONECANPAY`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsKindError;

impl fmt::Display for PrevoutsKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "single prevout provided but all prevouts are needed without `ANYONECANPAY`")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsKindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// [`Prevouts`] index related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrevoutsIndexError {
    /// Invalid index when accessing a [`Prevouts::One`] kind.
    InvalidOneIndex,
    /// Invalid index when accessing a [`Prevouts::All`] kind.
    InvalidAllIndex,
}

internals::impl_from_infallible!(PrevoutsIndexError);

impl fmt::Display for PrevoutsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex => write!(f, "invalid index when accessing a Prevouts::One kind"),
            InvalidAllIndex => write!(f, "invalid index when accessing a Prevouts::All kind"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex | InvalidAllIndex => None,
        }
    }
}

impl<'s> ScriptPath<'s> {
    /// Creates a new `ScriptPath` structure.
    pub fn new(script: &'s Script, leaf_version: LeafVersion) -> Self {
        ScriptPath { script, leaf_version }
    }
    /// Creates a new `ScriptPath` structure using default leaf version value.
    pub fn with_defaults(script: &'s Script) -> Self { Self::new(script, LeafVersion::TapScript) }
    /// Computes the leaf hash for this `ScriptPath`.
    pub fn leaf_hash(&self) -> TapLeafHash {
        let mut enc = TapLeafHash::engine();

        self.leaf_version
            .to_consensus()
            .consensus_encode(&mut enc)
            .expect("writing to hash enging should never fail");
        self.script.consensus_encode(&mut enc).expect("writing to hash enging should never fail");

        TapLeafHash::from_engine(enc)
    }
}

impl<'s> From<ScriptPath<'s>> for TapLeafHash {
    fn from(script_path: ScriptPath<'s>) -> TapLeafHash { script_path.leaf_hash() }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding (see also
/// [`TapSighashType`]).
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
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
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EcdsaSighashType::*;

        let s = match self {
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EcdsaSighashType::*;

        match s {
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        use EcdsaSighashType::*;

        match self {
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> EcdsaSighashType {
        use EcdsaSighashType::*;

        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => AllPlusAnyoneCanPay,
            _ => All,
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        use EcdsaSighashType::*;

        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(All),
            0x02 => Ok(None),
            0x03 => Ok(Single),
            0x81 => Ok(AllPlusAnyoneCanPay),
            0x82 => Ok(NonePlusAnyoneCanPay),
            0x83 => Ok(SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

impl From<EcdsaSighashType> for TapSighashType {
    fn from(s: EcdsaSighashType) -> Self {
        use TapSighashType::*;

        match s {
            EcdsaSighashType::All => All,
            EcdsaSighashType::None => None,
            EcdsaSighashType::Single => Single,
            EcdsaSighashType::AllPlusAnyoneCanPay => AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay => NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay => SinglePlusAnyoneCanPay,
        }
    }
}

impl TapSighashType {
    /// Breaks the sighash flag into the "real" sighash flag and the `SIGHASH_ANYONECANPAY` boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (TapSighashType, bool) {
        use TapSighashType::*;

        match self {
            Default => (Default, false),
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Constructs a [`TapSighashType`] from a raw `u8`.
    pub fn from_consensus_u8(sighash_type: u8) -> Result<Self, InvalidSighashTypeError> {
        use TapSighashType::*;

        Ok(match sighash_type {
            0x00 => Default,
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            x => return Err(InvalidSighashTypeError(x.into())),
        })
    }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSighashTypeError(pub u32);

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// The sighash components are computed in a lazy manner when required. For the generated
    /// sighashes to be valid, no fields in the transaction may change except for script_sig and
    /// witness.
    pub fn new(tx: R) -> Self {
        SighashCache { tx, common_cache: None, taproot_cache: None, segwit_cache: None }
    }

    /// Returns the reference to the cached transaction.
    pub fn transaction(&self) -> &Transaction { self.tx.borrow() }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R { self.tx }

    /// Encodes the BIP341 signing data for any flag type into a given object implementing the
    /// [`io::Write`] trait.
    pub fn taproot_encode_signing_data_to<W: Write + ?Sized, T: Borrow<TxOut>>(
        &mut self,
        writer: &mut W,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: TapSighashType,
    ) -> Result<(), SigningDataError<TaprootError>> {
        prevouts.check_all(self.tx.borrow()).map_err(SigningDataError::sighash)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // epoch
        0u8.consensus_encode(writer)?;

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.borrow().version.consensus_encode(writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.borrow().lock_time.consensus_encode(writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(writer)?;
            self.taproot_cache(prevouts.get_all().map_err(SigningDataError::sighash)?)
                .amounts
                .consensus_encode(writer)?;
            self.taproot_cache(prevouts.get_all().map_err(SigningDataError::sighash)?)
                .script_pubkeys
                .consensus_encode(writer)?;
            self.common_cache().sequences.consensus_encode(writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != TapSighashType::None && sighash != TapSighashType::Single {
            self.common_cache().outputs.consensus_encode(writer)?;
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
        spend_type.consensus_encode(writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      amount (8): value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin = &self.tx.borrow().tx_in(input_index).map_err(SigningDataError::sighash)?;
            let previous_output = prevouts.get(input_index).map_err(SigningDataError::sighash)?;
            txin.previous_output.consensus_encode(writer)?;
            previous_output.value.consensus_encode(writer)?;
            previous_output.script_pubkey.consensus_encode(writer)?;
            txin.sequence.consensus_encode(writer)?;
        } else {
            (input_index as u32).consensus_encode(writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        if sighash == TapSighashType::Single {
            let mut enc = sha256::Hash::engine();
            self.tx
                .borrow()
                .output
                .get(input_index)
                .ok_or(TaprootError::SingleMissingOutput(SingleMissingOutputError {
                    input_index,
                    outputs_length: self.tx.borrow().output.len(),
                }))
                .map_err(SigningDataError::Sighash)?
                .consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.as_byte_array().consensus_encode(writer)?;
            KEY_VERSION_0.consensus_encode(writer)?;
            code_separator_pos.consensus_encode(writer)?;
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
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
    }

    /// Computes the BIP341 sighash for a key spend.
    pub fn taproot_key_spend_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            None,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
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
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
    }

    /// Encodes the BIP143 signing data for any flag type into a given object implementing the
    /// [`std::io::Write`] trait.
    ///
    /// `script_code` is dependent on the type of the spend transaction. For p2wpkh use
    /// [`Script::p2wpkh_script_code`], for p2wsh just pass in the witness script. (Also see
    /// [`Self::p2wpkh_signature_hash`] and [`SighashCache::p2wsh_signature_hash`].)
    pub fn segwit_v0_encode_signing_data_to<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        input_index: usize,
        script_code: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), SigningDataError<transaction::InputsIndexError>> {
        let zero_hash = sha256d::Hash::all_zeros();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.borrow().version.consensus_encode(writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(writer)?;
        } else {
            zero_hash.consensus_encode(writer)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            self.segwit_cache().sequences.consensus_encode(writer)?;
        } else {
            zero_hash.consensus_encode(writer)?;
        }

        {
            let txin = &self.tx.borrow().tx_in(input_index).map_err(SigningDataError::sighash)?;
            txin.previous_output.consensus_encode(writer)?;
            script_code.consensus_encode(writer)?;
            value.consensus_encode(writer)?;
            txin.sequence.consensus_encode(writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(writer)?;
        } else if sighash == EcdsaSighashType::Single && input_index < self.tx.borrow().output.len()
        {
            let mut single_enc = LegacySighash::engine();
            self.tx.borrow().output[input_index].consensus_encode(&mut single_enc)?;
            let hash = LegacySighash::from_engine(single_enc);
            writer.write_all(&hash[..])?;
        } else {
            writer.write_all(&zero_hash[..])?;
        }

        self.tx.borrow().lock_time.consensus_encode(writer)?;
        sighash_type.to_u32().consensus_encode(writer)?;
        Ok(())
    }

    /// Computes the BIP143 sighash to spend a p2wpkh transaction for any flag type.
    ///
    /// `script_pubkey` is the `scriptPubkey` (native segwit) of the spend transaction
    /// ([`TxOut::script_pubkey`]) or the `redeemScript` (wrapped segwit).
    pub fn p2wpkh_signature_hash(
        &mut self,
        input_index: usize,
        script_pubkey: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, P2wpkhError> {
        let script_code = script_pubkey.p2wpkh_script_code().ok_or(P2wpkhError::NotP2wpkhScript)?;

        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            &script_code,
            value,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Computes the BIP143 sighash to spend a p2wsh transaction for any flag type.
    pub fn p2wsh_signature_hash(
        &mut self,
        input_index: usize,
        witness_script: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, transaction::InputsIndexError> {
        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            witness_script,
            value,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Encodes the legacy signing data from which a signature hash for a given input index with a
    /// given sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    /// - Does NOT handle the sighash single bug (see "Return type" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    pub fn legacy_encode_signing_data_to<W: Write + ?Sized, U: Into<u32>>(
        &self,
        writer: &mut W,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> EncodeSigningDataResult<SigningDataError<transaction::InputsIndexError>> {
        // Validate input_index.
        if let Err(e) = self.tx.borrow().tx_in(input_index) {
            return EncodeSigningDataResult::WriteResult(Err(SigningDataError::Sighash(e)));
        }
        let sighash_type: u32 = sighash_type.into();

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().output.len(),
        ) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behaviour manually or use `signature_hash()`.
            return EncodeSigningDataResult::SighashSingleBug;
        }

        fn encode_signing_data_to_inner<W: Write + ?Sized>(
            self_: &Transaction,
            writer: &mut W,
            input_index: usize,
            script_pubkey: &Script,
            sighash_type: u32,
        ) -> Result<(), io::Error> {
            let (sighash, anyone_can_pay) =
                EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

            // Build tx to sign
            let mut tx = Transaction {
                version: self_.version,
                lock_time: self_.lock_time,
                input: vec![],
                output: vec![],
            };
            // Add all inputs necessary..
            if anyone_can_pay {
                tx.input = vec![TxIn {
                    previous_output: self_.input[input_index].previous_output,
                    script_sig: script_pubkey.to_owned(),
                    sequence: self_.input[input_index].sequence,
                    witness: Witness::default(),
                }];
            } else {
                tx.input = Vec::with_capacity(self_.input.len());
                for (n, input) in self_.input.iter().enumerate() {
                    tx.input.push(TxIn {
                        previous_output: input.previous_output,
                        script_sig: if n == input_index {
                            script_pubkey.to_owned()
                        } else {
                            ScriptBuf::new()
                        },
                        sequence: if n != input_index
                            && (sighash == EcdsaSighashType::Single
                                || sighash == EcdsaSighashType::None)
                        {
                            Sequence::ZERO
                        } else {
                            input.sequence
                        },
                        witness: Witness::default(),
                    });
                }
            }
            // ..then all outputs
            tx.output = match sighash {
                EcdsaSighashType::All => self_.output.clone(),
                EcdsaSighashType::Single => {
                    let output_iter = self_
                        .output
                        .iter()
                        .take(input_index + 1) // sign all outputs up to and including this one, but erase
                        .enumerate() // all of them except for this one
                        .map(|(n, out)| if n == input_index { out.clone() } else { TxOut::NULL });
                    output_iter.collect()
                }
                EcdsaSighashType::None => vec![],
                _ => unreachable!(),
            };
            // hash the result
            tx.consensus_encode(writer)?;
            sighash_type.to_le_bytes().consensus_encode(writer)?;
            Ok(())
        }

        EncodeSigningDataResult::WriteResult(
            encode_signing_data_to_inner(
                self.tx.borrow(),
                writer,
                input_index,
                script_pubkey,
                sighash_type,
            )
            .map_err(Into::into),
        )
    }

    /// Computes a legacy signature hash for a given input index with a given sighash flag.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// This function correctly handles the sighash single bug by returning the 'one array'. The
    /// sighash single bug becomes exploitable when one tries to sign a transaction with
    /// `SIGHASH_SINGLE` and there is not a corresponding output with the same index as the input.
    ///
    /// # Warning
    ///
    /// Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<LegacySighash, transaction::InputsIndexError> {
        let mut engine = LegacySighash::engine();
        match self
            .legacy_encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()
        {
            Ok(true) => Ok(LegacySighash::from_byte_array(UINT256_ONE)),
            Ok(false) => Ok(LegacySighash::from_engine(engine)),
            Err(e) => Err(e.unwrap_sighash()),
        }
    }

    #[inline]
    fn common_cache(&mut self) -> &CommonCache {
        Self::common_cache_minimal_borrow(&mut self.common_cache, self.tx.borrow())
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &Transaction,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output.consensus_encode(&mut enc_prevouts).unwrap();
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
        let tx = self.tx.borrow();
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: common_cache.prevouts.hash_again(),
                sequences: common_cache.sequences.hash_again(),
                outputs: common_cache.outputs.hash_again(),
            }
        })
    }

    fn taproot_cache<T: Borrow<TxOut>>(&mut self, prevouts: &[T]) -> &TaprootCache {
        self.taproot_cache.get_or_insert_with(|| {
            let mut enc_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.borrow().value.consensus_encode(&mut enc_amounts).unwrap();
                prevout.borrow().script_pubkey.consensus_encode(&mut enc_script_pubkeys).unwrap();
            }
            TaprootCache {
                amounts: sha256::Hash::from_engine(enc_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
            }
        })
    }
}

impl<R: BorrowMut<Transaction>> SighashCache<R> {
    /// Allows modification of witnesses.
    ///
    /// As a lint against accidental changes to the transaction that would invalidate the cache and
    /// signatures, `SighashCache` borrows the Transaction so that modifying it is not possible
    /// without hacks with `UnsafeCell` (which is hopefully a strong indication that something is
    /// wrong). However modifying witnesses never invalidates the cache and is actually useful - one
    /// usually wants to put the signature generated for an input into the witness of that input.
    ///
    /// This method allows doing exactly that if the transaction is owned by the `SighashCache` or
    /// borrowed mutably.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// let mut sighasher = SighashCache::new(&mut tx_to_sign);
    /// let sighash = sighasher.p2wpkh_signature_hash(input_index, &utxo.script_pubkey, amount, sighash_type)?;
    ///
    /// let signature = {
    ///     // Sign the sighash using secp256k1
    /// };
    ///
    /// *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk);
    /// ```
    ///
    /// For full signing code see the [`segwit v0`] and [`taproot`] signing examples.
    ///
    /// [`segwit v0`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-segwit-v0.rs>
    /// [`taproot`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-taproot.rs>
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.borrow_mut().input.get_mut(input_index).map(|i| &mut i.witness)
    }
}

/// The `Annex` struct is a slice wrapper enforcing first byte is `0x50`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`.
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, AnnexError> {
        use AnnexError::*;

        match annex_bytes.first() {
            Some(&TAPROOT_ANNEX_PREFIX) => Ok(Annex(annex_bytes)),
            Some(other) => Err(IncorrectPrefix(*other)),
            None => Err(Empty),
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`).
    pub fn as_bytes(&self) -> &[u8] { self.0 }
}

impl<'a> Encodable for Annex<'a> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self.0, w)
    }
}

/// Error computing a taproot sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaprootError {
    /// Index out of bounds when accessing transaction input vector.
    InputsIndex(transaction::InputsIndexError),
    /// Using `SIGHASH_SINGLE` requires an output at the same index is the input.
    SingleMissingOutput(SingleMissingOutputError),
    /// Prevouts size error.
    PrevoutsSize(PrevoutsSizeError),
    /// Prevouts index error.
    PrevoutsIndex(PrevoutsIndexError),
    /// Prevouts kind error.
    PrevoutsKind(PrevoutsKindError),
    /// Invalid Sighash type.
    InvalidSighashType(u32),
}

internals::impl_from_infallible!(TaprootError);

impl fmt::Display for TaprootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TaprootError::*;

        match *self {
            InputsIndex(ref e) => write_err!(f, "inputs index"; e),
            SingleMissingOutput(ref e) => write_err!(f, "sighash single"; e),
            PrevoutsSize(ref e) => write_err!(f, "prevouts size"; e),
            PrevoutsIndex(ref e) => write_err!(f, "prevouts index"; e),
            PrevoutsKind(ref e) => write_err!(f, "prevouts kind"; e),
            InvalidSighashType(hash_ty) => write!(f, "invalid taproot sighash type : {} ", hash_ty),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TaprootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TaprootError::*;

        match *self {
            InputsIndex(ref e) => Some(e),
            SingleMissingOutput(ref e) => Some(e),
            PrevoutsSize(ref e) => Some(e),
            PrevoutsIndex(ref e) => Some(e),
            PrevoutsKind(ref e) => Some(e),
            InvalidSighashType(_) => None,
        }
    }
}

impl From<transaction::InputsIndexError> for TaprootError {
    fn from(e: transaction::InputsIndexError) -> Self { Self::InputsIndex(e) }
}

impl From<PrevoutsSizeError> for TaprootError {
    fn from(e: PrevoutsSizeError) -> Self { Self::PrevoutsSize(e) }
}

impl From<PrevoutsKindError> for TaprootError {
    fn from(e: PrevoutsKindError) -> Self { Self::PrevoutsKind(e) }
}

impl From<PrevoutsIndexError> for TaprootError {
    fn from(e: PrevoutsIndexError) -> Self { Self::PrevoutsIndex(e) }
}

/// Error computing a P2WPKH sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum P2wpkhError {
    /// Error computing the sighash.
    Sighash(transaction::InputsIndexError),
    /// Script is not a witness program for a p2wpkh output.
    NotP2wpkhScript,
}

internals::impl_from_infallible!(P2wpkhError);

impl From<transaction::InputsIndexError> for P2wpkhError {
    fn from(value: transaction::InputsIndexError) -> Self { P2wpkhError::Sighash(value) }
}

impl fmt::Display for P2wpkhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use P2wpkhError::*;

        match *self {
            Sighash(ref e) => write_err!(f, "error encoding segwit v0 signing data"; e),
            NotP2wpkhScript => write!(f, "script is not a script pubkey for a p2wpkh output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for P2wpkhError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use P2wpkhError::*;

        match *self {
            Sighash(ref e) => Some(e),
            NotP2wpkhScript => None,
        }
    }
}

/// Using `SIGHASH_SINGLE` requires an output at the same index as the input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SingleMissingOutputError {
    /// Input index.
    pub input_index: usize,
    /// Length of the output vector.
    pub outputs_length: usize,
}

impl fmt::Display for SingleMissingOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sighash single requires an output at the same index as the input \
             (input index: {}, outputs length: {})",
            self.input_index, self.outputs_length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SingleMissingOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Annex must be at least one byte long and the first bytes must be `0x50`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnexError {
    /// The annex is empty.
    Empty,
    /// Incorrect prefix byte in the annex.
    IncorrectPrefix(u8),
}

internals::impl_from_infallible!(AnnexError);

impl fmt::Display for AnnexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AnnexError::*;

        match *self {
            Empty => write!(f, "the annex is empty"),
            IncorrectPrefix(byte) =>
                write!(f, "incorrect prefix byte in the annex {:02x}, expecting 0x50", byte),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnnexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use AnnexError::*;

        match *self {
            Empty | IncorrectPrefix(_) => None,
        }
    }
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, outputs_len: usize) -> bool {
    let ty = EcdsaSighashType::from_consensus(sighash);
    ty == EcdsaSighashType::Single && input_index >= outputs_len
}

/// Result of [`SighashCache::legacy_encode_signing_data_to`].
///
/// This type forces the caller to handle SIGHASH_SINGLE bug case.
///
/// This corner case can't be expressed using standard `Result`,
/// in a way that is both convenient and not-prone to accidental
/// mistakes (like calling `.expect("writer never fails")`).
#[must_use]
pub enum EncodeSigningDataResult<E> {
    /// Input data is an instance of `SIGHASH_SINGLE` bug
    SighashSingleBug,
    /// Operation performed normally.
    WriteResult(Result<(), E>),
}

impl<E> EncodeSigningDataResult<E> {
    /// Checks for SIGHASH_SINGLE bug returning error if the writer failed.
    ///
    /// This method is provided for easy and correct handling of the result because
    /// SIGHASH_SINGLE bug is a special case that must not be ignored nor cause panicking.
    /// Since the data is usually written directly into a hasher which never fails,
    /// the recommended pattern to handle this is:
    ///
    /// ```rust
    /// # use bitcoin::consensus::deserialize;
    /// # use bitcoin::hashes::{Hash, hex::FromHex};
    /// # use bitcoin::sighash::{LegacySighash, SighashCache};
    /// # use bitcoin::Transaction;
    /// # let mut writer = LegacySighash::engine();
    /// # let input_index = 0;
    /// # let script_pubkey = bitcoin::ScriptBuf::new();
    /// # let sighash_u32 = 0u32;
    /// # const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    /// # let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    /// # let tx: Transaction = deserialize(&raw_tx).unwrap();
    /// let cache = SighashCache::new(&tx);
    /// if cache.legacy_encode_signing_data_to(&mut writer, input_index, &script_pubkey, sighash_u32)
    ///         .is_sighash_single_bug()
    ///         .expect("writer can't fail") {
    ///     // use a hash value of "1", instead of computing the actual hash due to SIGHASH_SINGLE bug
    /// }
    /// ```
    pub fn is_sighash_single_bug(self) -> Result<bool, E> {
        match self {
            EncodeSigningDataResult::SighashSingleBug => Ok(true),
            EncodeSigningDataResult::WriteResult(Ok(())) => Ok(false),
            EncodeSigningDataResult::WriteResult(Err(e)) => Err(e),
        }
    }

    /// Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a
    /// contained [`Err`] value, leaving an [`Ok`] value untouched.
    ///
    /// Like [`Result::map_err`].
    pub fn map_err<E2, F>(self, f: F) -> EncodeSigningDataResult<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            EncodeSigningDataResult::SighashSingleBug => EncodeSigningDataResult::SighashSingleBug,
            EncodeSigningDataResult::WriteResult(Err(e)) =>
                EncodeSigningDataResult::WriteResult(Err(f(e))),
            EncodeSigningDataResult::WriteResult(Ok(o)) =>
                EncodeSigningDataResult::WriteResult(Ok(o)),
        }
    }
}

/// Error returned when writing signing data fails.
#[derive(Debug)]
pub enum SigningDataError<E> {
    /// Can happen only when using `*_encode_signing_*` methods with custom writers, engines
    /// like those used in `*_signature_hash` methods do not error.
    Io(io::Error),
    /// An argument to the called sighash function was invalid.
    Sighash(E),
}

internals::impl_from_infallible!(SigningDataError<E>);

impl<E> SigningDataError<E> {
    /// Returns the sighash variant, panicking if it's IO.
    ///
    /// This is used when encoding to hash engine when we know that IO doesn't fail.
    fn unwrap_sighash(self) -> E {
        match self {
            Self::Sighash(error) => error,
            Self::Io(error) => panic!("hash engine error {}", error),
        }
    }

    fn sighash<E2: Into<E>>(error: E2) -> Self { Self::Sighash(error.into()) }
}

// We cannot simultaneously impl `From<E>`. it was determined that this alternative requires less
// manual `map_err` calls.
impl<E> From<io::Error> for SigningDataError<E> {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

impl<E: fmt::Display> fmt::Display for SigningDataError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(error) => write_err!(f, "failed to write sighash data"; error),
            Self::Sighash(error) => write_err!(f, "failed to compute sighash data"; error),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for SigningDataError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SigningDataError::Io(error) => Some(error),
            SigningDataError::Sighash(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hashes::HashEngine;
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::consensus::deserialize;

    extern crate serde_json;

    #[test]
    fn sighash_single_bug() {
        const SIGHASH_SINGLE: u32 = 3;

        // We need a tx with more inputs than outputs.
        let tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut::NULL],
        };
        let script = ScriptBuf::new();
        let cache = SighashCache::new(&tx);

        let got = cache.legacy_signature_hash(1, &script, SIGHASH_SINGLE).expect("sighash");
        let want = LegacySighash::from_slice(&UINT256_ONE).unwrap();

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(feature = "serde")]
    fn legacy_sighash() {
        use serde_json::Value;

        use crate::sighash::SighashCache;

        fn run_test_sighash(
            tx: &str,
            script: &str,
            input_index: usize,
            hash_type: i64,
            expected_result: &str,
        ) {
            let tx: Transaction = deserialize(&Vec::from_hex(tx).unwrap()[..]).unwrap();
            let script = ScriptBuf::from(Vec::from_hex(script).unwrap());
            let mut raw_expected = Vec::from_hex(expected_result).unwrap();
            raw_expected.reverse();
            let want = LegacySighash::from_slice(&raw_expected[..]).unwrap();

            let cache = SighashCache::new(&tx);
            let got = cache.legacy_signature_hash(input_index, &script, hash_type as u32).unwrap();

            assert_eq!(got, want);
        }

        // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
        // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
        // OP_CODESEPARATOR in their pubkeys were removed
        let data = include_str!("../../tests/data/legacy_sighash.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let tx = t.get(0).unwrap().as_str().unwrap();
            let script = t.get(1).unwrap().as_str().unwrap_or("");
            let input_index = t.get(2).unwrap().as_u64().unwrap();
            let hash_type = t.get(3).unwrap().as_i64().unwrap();
            let expected_sighash = t.get(4).unwrap().as_str().unwrap();
            run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
        }
    }

    #[test]
    fn test_tap_sighash_hash() {
        let bytes = hex!("00011b96877db45ffa23b307e9f0ac87b80ef9a80b4c5f0db3fbe734422453e83cc5576f3d542c5d4898fb2b696c15d43332534a7c1d1255fda38993545882df92c3e353ff6d36fbfadc4d168452afd8467f02fe53d71714fcea5dfe2ea759bd00185c4cb02bc76d42620393ca358a1a713f4997f9fc222911890afb3fe56c6a19b202df7bffdcfad08003821294279043746631b00e2dc5e52a111e213bbfe6ef09a19428d418dab0d50000000000");
        let expected = hex!("04e808aad07a40b3767a1442fead79af6ef7e7c9316d82dec409bb31e77699b0");
        let mut enc = TapSighash::engine();
        enc.input(&bytes);
        let hash = TapSighash::from_engine(enc);
        assert_eq!(expected, hash.to_byte_array());
    }

    #[test]
    fn test_sighashes_keyspending() {
        // following test case has been taken from Bitcoin Core test framework

        test_taproot_sighash(
            "020000000164eb050a5e3da0c2a65e4786f26d753b7bc69691fabccafb11f7acef36641f1846010000003101b2b404392a22000000000017a9147f2bde86fe78bf68a0544a4f290e12f0b7e0a08c87580200000000000017a91425d11723074ecfb96a0a83c3956bfaf362ae0c908758020000000000001600147e20f938993641de67bb0cdd71682aa34c4d29ad5802000000000000160014c64984dc8761acfa99418bd6bedc79b9287d652d72000000",
            "01365724000000000023542156b39dab4f8f3508e0432cfb41fab110170acaa2d4c42539cb90a4dc7c093bc500",
            0,
            "33ca0ebfb4a945eeee9569fc0f5040221275f88690b7f8592ada88ce3bdf6703",
            TapSighashType::Default, None, None, None
        );

        test_taproot_sighash(
            "0200000002fff49be59befe7566050737910f6ccdc5e749c7f8860ddc140386463d88c5ad0f3000000002cf68eb4a3d67f9d4c079249f7e4f27b8854815cb1ed13842d4fbf395f9e217fd605ee24090100000065235d9203f458520000000000160014b6d48333bb13b4c644e57c43a9a26df3a44b785e58020000000000001976a914eea9461a9e1e3f765d3af3e726162e0229fe3eb688ac58020000000000001976a9143a8869c9f2b5ea1d4ff3aeeb6a8fb2fffb1ad5fe88ac0ad7125c",
            "02591f220000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece48fb310000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece",
            1,
            "626ab955d58c9a8a600a0c580549d06dc7da4e802eb2a531f62a588e430967a8",
            TapSighashType::All, None, None, None
        );

        test_taproot_sighash(
            "0200000001350005f65aa830ced2079df348e2d8c2bdb4f10e2dde6a161d8a07b40d1ad87dae000000001611d0d603d9dc0e000000000017a914459b6d7d6bbb4d8837b4bf7e9a4556f952da2f5c8758020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88ac58020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88aca71c1f4f",
            "01c4811000000000002251201bf9297d0a2968ae6693aadd0fa514717afefd218087a239afb7418e2d22e65c",
            0,
            "dfa9437f9c9a1d1f9af271f79f2f5482f287cdb0d2e03fa92c8a9b216cc6061c",
            TapSighashType::AllPlusAnyoneCanPay, None, None, None
        );

        test_taproot_sighash(
            "020000000185bed1a6da2bffbd60ec681a1bfb71c5111d6395b99b3f8b2bf90167111bcb18f5010000007c83ace802ded24a00000000001600142c4698f9f7a773866879755aa78c516fb332af8e5802000000000000160014d38639dfbac4259323b98a472405db0c461b31fa61073747",
            "0144c84d0000000000225120e3f2107989c88e67296ab2faca930efa2e3a5bd3ff0904835a11c9e807458621",
            0,
            "3129de36a5d05fff97ffca31eb75fcccbbbc27b3147a7a36a9e4b45d8b625067",
            TapSighashType::None, None, None, None
        );

        test_taproot_sighash(
            "eb93dbb901028c8515589dac980b6e7f8e4088b77ed866ca0d6d210a7218b6fd0f6b22dd6d7300000000eb4740a9047efc0e0000000000160014913da2128d8fcf292b3691db0e187414aa1783825802000000000000160014913da2128d8fcf292b3691db0e187414aa178382580200000000000017a9143dd27f01c6f7ef9bb9159937b17f17065ed01a0c875802000000000000160014d7630e19df70ada9905ede1722b800c0005f246641000000",
            "013fed110000000000225120eb536ae8c33580290630fc495046e998086a64f8f33b93b07967d9029b265c55",
            0,
            "2441e8b0e063a2083ee790f14f2045022f07258ddde5ee01de543c9e789d80ae",
            TapSighashType::NonePlusAnyoneCanPay, None, None, None
        );

        test_taproot_sighash(
            "02000000017836b409a5fed32211407e44b971591f2032053f14701fb5b3a30c0ff382f2cc9c0100000061ac55f60288fb5600000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ac58020000000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ace4000000",
            "01efa558000000000022512007071ea3dc7e331b0687d0193d1e6d6ed10e645ef36f10ef8831d5e522ac9e80",
            0,
            "30239345177cadd0e3ea413d49803580abb6cb27971b481b7788a78d35117a88",
            TapSighashType::Single, None, None, None
        );

        test_taproot_sighash(
            "0100000001aa6deae89d5e0aaca58714fc76ef6f3c8284224888089232d4e663843ed3ab3eae010000008b6657a60450cb4c0000000000160014a3d42b5413ef0c0701c4702f3cd7d4df222c147058020000000000001976a91430b4ed8723a4ee8992aa2c8814cfe5c3ad0ab9d988ac5802000000000000160014365b1166a6ed0a5e8e9dff17a6d00bbb43454bc758020000000000001976a914bc98c51a84fe7fad5dc380eb8b39586eff47241688ac4f313247",
            "0107af4e00000000002251202c36d243dfc06cb56a248e62df27ecba7417307511a81ae61aa41c597a929c69",
            0,
            "bf9c83f26c6dd16449e4921f813f551c4218e86f2ec906ca8611175b41b566df",
            TapSighashType::SinglePlusAnyoneCanPay, None, None, None
        );
    }

    #[test]
    fn test_sighashes_with_annex() {
        test_taproot_sighash(
            "0200000001df8123752e8f37d132c4e9f1ff7e4f9b986ade9211267e9ebd5fd22a5e718dec6d01000000ce4023b903cb7b23000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787580200000000000017a914afd0d512a2c5c2b40e25669e9cc460303c325b8b87580200000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787f6020000",
            "01ea49260000000000225120ab5e9800806bf18cb246edcf5fe63441208fe955a4b5a35bbff65f5db622a010",
            0,
            "3b003000add359a364a156e73e02846782a59d0d95ca8c4638aaad99f2ef915c",
            TapSighashType::SinglePlusAnyoneCanPay,
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
            TapSighashType::All,
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
            TapSighashType::All,
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
            TapSighashType::All,
            Some("50a6272b470e1460e3332ade7bb14b81671c564fb6245761bd5bd531394b28860e0b3808ab229fb51791fb6ae6fa82d915b2efb8f6df83ae1f5ab3db13e30928875e2a22b749d89358de481f19286cd4caa792ce27f9559082d227a731c5486882cc707f83da361c51b7aadd9a0cf68fe7480c410fa137b454482d9a1ebf0f96d760b4d61426fc109c6e8e99a508372c45caa7b000a41f8251305da3f206c1849985ba03f3d9592832b4053afbd23ab25d0465df0bc25a36c223aacf8e04ec736a418c72dc319e4da3e972e349713ca600965e7c665f2090d5a70e241ac164115a1f5639f28b1773327715ca307ace64a2de7f0e3df70a2ffee3857689f909c0dad46d8a20fa373a4cc6eed6d4c9806bf146f0d76baae1"),
            Some("7520ab9160dd8299dc1367659be3e8f66781fe440d52940c7f8d314a89b9f2698d406ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6eadac"),
            None,
        );
    }

    #[test]
    #[rustfmt::skip] // Allow long function call `taproot_signature_hash`.
    fn test_sighash_errors() {
        use crate::transaction::{IndexOutOfBoundsError, InputsIndexError};

        let dumb_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let mut c = SighashCache::new(&dumb_tx);

        // 1.29 fixes
        let empty_vec = vec![];
        let empty_prevouts : Prevouts<TxOut> = Prevouts::All(&empty_vec);
        assert_eq!(
            c.taproot_signature_hash(0, &empty_prevouts, None, None, TapSighashType::All),
            Err(TaprootError::PrevoutsSize(PrevoutsSizeError))
        );
        let two = vec![TxOut::NULL, TxOut::NULL];
        let too_many_prevouts = Prevouts::All(&two);
        assert_eq!(
            c.taproot_signature_hash(0, &too_many_prevouts, None, None, TapSighashType::All),
            Err(TaprootError::PrevoutsSize(PrevoutsSizeError))
        );
        let tx_out = TxOut::NULL;
        let prevout = Prevouts::One(1, &tx_out);
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, TapSighashType::All),
            Err(TaprootError::PrevoutsKind(PrevoutsKindError))
        );
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, TapSighashType::AllPlusAnyoneCanPay),
            Err(TaprootError::PrevoutsIndex(PrevoutsIndexError::InvalidOneIndex))
        );
        assert_eq!(
            c.taproot_signature_hash(10, &prevout, None, None, TapSighashType::AllPlusAnyoneCanPay),
            Err(InputsIndexError(IndexOutOfBoundsError {
                index: 10,
                length: 1
            }).into())
        );
        let prevout = Prevouts::One(0, &tx_out);
        assert_eq!(
            c.taproot_signature_hash(0, &prevout, None, None, TapSighashType::SinglePlusAnyoneCanPay),
            Err(TaprootError::SingleMissingOutput(SingleMissingOutputError {
                input_index: 0,
                outputs_length: 0
            }))
        );
        assert_eq!(
            c.legacy_signature_hash(10, Script::new(), 0u32),
            Err(InputsIndexError(IndexOutOfBoundsError {
                index: 10,
                length: 1
            }))
        );
    }

    #[test]
    fn test_annex_errors() {
        assert_eq!(Annex::new(&[]), Err(AnnexError::Empty));
        assert_eq!(Annex::new(&[0x51]), Err(AnnexError::IncorrectPrefix(0x51)));
        assert_eq!(Annex::new(&[0x51, 0x50]), Err(AnnexError::IncorrectPrefix(0x51)));
    }

    #[allow(clippy::too_many_arguments)]
    fn test_taproot_sighash(
        tx_hex: &str,
        prevout_hex: &str,
        input_index: usize,
        expected_hash: &str,
        sighash_type: TapSighashType,
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

        let leaf_hash = match (script_hex, script_leaf_hash) {
            (Some(script_hex), _) => {
                let script_inner = ScriptBuf::from_hex(script_hex).unwrap();
                Some(ScriptPath::with_defaults(&script_inner).leaf_hash())
            }
            (_, Some(script_leaf_hash)) => Some(script_leaf_hash.parse::<TapLeafHash>().unwrap()),
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
        assert_eq!(expected, hash.to_byte_array());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn bip_341_sighash_tests() {
        use hex::DisplayHex;

        fn sighash_deser_numeric<'de, D>(deserializer: D) -> Result<TapSighashType, D::Error>
        where
            D: actual_serde::Deserializer<'de>,
        {
            use actual_serde::de::{Deserialize, Error, Unexpected};

            let raw = u8::deserialize(deserializer)?;
            TapSighashType::from_consensus_u8(raw).map_err(|_| {
                D::Error::invalid_value(
                    Unexpected::Unsigned(raw.into()),
                    &"number in range 0-3 or 0x81-0x83",
                )
            })
        }

        use secp256k1::{SecretKey, XOnlyPublicKey};

        use crate::consensus::serde as con_serde;
        use crate::taproot::{TapNodeHash, TapTweakHash};

        #[derive(serde::Deserialize)]
        #[serde(crate = "actual_serde")]
        struct UtxoSpent {
            #[serde(rename = "scriptPubKey")]
            script_pubkey: ScriptBuf,
            #[serde(rename = "amountSats")]
            value: Amount,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsGiven {
            #[serde(with = "con_serde::With::<con_serde::Hex>")]
            raw_unsigned_tx: Transaction,
            utxos_spent: Vec<UtxoSpent>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsIntermediary {
            hash_prevouts: sha256::Hash,
            hash_outputs: sha256::Hash,
            hash_sequences: sha256::Hash,
            hash_amounts: sha256::Hash,
            hash_script_pubkeys: sha256::Hash,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsInputSpendingGiven {
            txin_index: usize,
            internal_privkey: SecretKey,
            merkle_root: Option<TapNodeHash>,
            #[serde(deserialize_with = "sighash_deser_numeric")]
            hash_type: TapSighashType,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsInputSpendingIntermediary {
            internal_pubkey: XOnlyPublicKey,
            tweak: TapTweakHash,
            tweaked_privkey: SecretKey,
            sig_msg: String,
            //precomputed_used: Vec<String>, // unused
            sig_hash: TapSighash,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsInputSpendingExpected {
            witness: Vec<String>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KpsInputSpending {
            given: KpsInputSpendingGiven,
            intermediary: KpsInputSpendingIntermediary,
            expected: KpsInputSpendingExpected,
            // auxiliary: KpsAuxiliary, //unused
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct KeyPathSpending {
            given: KpsGiven,
            intermediary: KpsIntermediary,
            input_spending: Vec<KpsInputSpending>,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        #[serde(crate = "actual_serde")]
        struct TestData {
            version: u64,
            key_path_spending: Vec<KeyPathSpending>,
            //script_pubkey: Vec<ScriptPubKey>, // unused
        }

        let json_str = include_str!("../../tests/data/bip341_tests.json");
        let mut data =
            serde_json::from_str::<TestData>(json_str).expect("JSON was not well-formatted");

        assert_eq!(data.version, 1u64);
        let secp = &secp256k1::Secp256k1::new();
        let key_path = data.key_path_spending.remove(0);

        let raw_unsigned_tx = key_path.given.raw_unsigned_tx;
        let utxos = key_path
            .given
            .utxos_spent
            .into_iter()
            .map(|txo| TxOut { value: txo.value, script_pubkey: txo.script_pubkey })
            .collect::<Vec<_>>();

        // Test intermediary
        let mut cache = SighashCache::new(&raw_unsigned_tx);

        let expected = key_path.intermediary;
        // Compute all caches
        assert_eq!(expected.hash_amounts, cache.taproot_cache(&utxos).amounts);
        assert_eq!(expected.hash_outputs, cache.common_cache().outputs);
        assert_eq!(expected.hash_prevouts, cache.common_cache().prevouts);
        assert_eq!(expected.hash_script_pubkeys, cache.taproot_cache(&utxos).script_pubkeys);
        assert_eq!(expected.hash_sequences, cache.common_cache().sequences);

        for mut inp in key_path.input_spending {
            let tx_ind = inp.given.txin_index;
            let internal_priv_key = inp.given.internal_privkey;
            let merkle_root = inp.given.merkle_root;
            let hash_ty = inp.given.hash_type;

            let expected = inp.intermediary;
            let sig_str = inp.expected.witness.remove(0);
            let (expected_key_spend_sig, expected_hash_ty) = if sig_str.len() == 128 {
                (
                    secp256k1::schnorr::Signature::from_str(&sig_str).unwrap(),
                    TapSighashType::Default,
                )
            } else {
                let hash_ty = u8::from_str_radix(&sig_str[128..130], 16).unwrap();
                let hash_ty = TapSighashType::from_consensus_u8(hash_ty).unwrap();
                (secp256k1::schnorr::Signature::from_str(&sig_str[..128]).unwrap(), hash_ty)
            };

            // tests
            let keypair = secp256k1::Keypair::from_secret_key(secp, &internal_priv_key);
            let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
            let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak.to_scalar()).unwrap();
            let mut sig_msg = Vec::new();
            cache
                .taproot_encode_signing_data_to(
                    &mut sig_msg,
                    tx_ind,
                    &Prevouts::All(&utxos),
                    None,
                    None,
                    hash_ty,
                )
                .unwrap();
            let sighash = cache
                .taproot_signature_hash(tx_ind, &Prevouts::All(&utxos), None, None, hash_ty)
                .unwrap();

            let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
            let key_spend_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

            assert_eq!(expected.internal_pubkey, internal_key);
            assert_eq!(expected.tweak, tweak);
            assert_eq!(expected.sig_msg, sig_msg.to_lower_hex_string());
            assert_eq!(expected.sig_hash, sighash);
            assert_eq!(expected_hash_ty, hash_ty);
            assert_eq!(expected_key_spend_sig, key_spend_sig);

            let tweaked_priv_key = SecretKey::from_keypair(&tweaked_keypair);
            assert_eq!(expected.tweaked_privkey, tweaked_priv_key);
        }
    }

    #[test]
    fn sighashtype_fromstr_display() {
        let sighashtypes = vec![
            ("SIGHASH_DEFAULT", TapSighashType::Default),
            ("SIGHASH_ALL", TapSighashType::All),
            ("SIGHASH_NONE", TapSighashType::None),
            ("SIGHASH_SINGLE", TapSighashType::Single),
            ("SIGHASH_ALL|SIGHASH_ANYONECANPAY", TapSighashType::AllPlusAnyoneCanPay),
            ("SIGHASH_NONE|SIGHASH_ANYONECANPAY", TapSighashType::NonePlusAnyoneCanPay),
            ("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY", TapSighashType::SinglePlusAnyoneCanPay),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(TapSighashType::from_str(s).unwrap(), sht);
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
            assert_eq!(
                TapSighashType::from_str(s).unwrap_err().to_string(),
                format!("unrecognized SIGHASH string '{}'", s)
            );
        }
    }

    #[test]
    fn bip143_p2wpkh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
                0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
                00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
                510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
            ),
        ).unwrap();

        let spk = ScriptBuf::from_hex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap();
        let value = Amount::from_sat(600_000_000);

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wpkh_signature_hash(1, &spk, value, EcdsaSighashType::All).unwrap(),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &Vec::from_hex("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &Vec::from_hex("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &Vec::from_hex("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5")
                .unwrap()[..],
        );
    }

    #[test]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
                0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
                08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
            ),
        ).unwrap();

        let redeem_script =
            ScriptBuf::from_hex("001479091972186c449eb1ded22b78e40d009bdf0089").unwrap();
        let value = Amount::from_sat(1_000_000_000);

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wpkh_signature_hash(0, &redeem_script, value, EcdsaSighashType::All).unwrap(),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &Vec::from_hex("b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &Vec::from_hex("18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &Vec::from_hex("de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83")
                .unwrap()[..],
        );
    }

    // Note, if you are looking at the test vectors in BIP-143 and wondering why there is a `cf`
    // prepended to all the script_code hex it is the length byte, it gets added when we consensus
    // encode a script.
    fn bip143_p2wsh_nested_in_p2sh_data() -> (Transaction, ScriptBuf, Amount) {
        let tx = deserialize::<Transaction>(&hex!(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        ))
        .unwrap();

        let witness_script = ScriptBuf::from_hex(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae",
        )
        .unwrap();

        let value = Amount::from_sat(987_654_321);
        (tx, witness_script, value)
    }

    #[test]
    fn bip143_p2wsh_nested_in_p2sh_sighash_type_all() {
        let (tx, witness_script, value) = bip143_p2wsh_nested_in_p2sh_data();
        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All).unwrap(),
            "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        // We only test the cache intermediate values for `EcdsaSighashType::All` because they are
        // not the same as the BIP test vectors for all the rest of the sighash types. These fields
        // are private so it does not effect sighash cache usage, we do test against the produced
        // sighash for all sighash types.

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            &Vec::from_hex("74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0")
                .unwrap()[..],
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            &Vec::from_hex("3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044")
                .unwrap()[..],
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            &Vec::from_hex("bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc")
                .unwrap()[..],
        );
    }

    macro_rules! check_bip143_p2wsh_nested_in_p2sh {
        ($($test_name:ident, $sighash_type:ident, $sighash:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    use EcdsaSighashType::*;

                    let (tx, witness_script, value) = bip143_p2wsh_nested_in_p2sh_data();
                    let mut cache = SighashCache::new(&tx);
                    assert_eq!(
                        cache
                            .p2wsh_signature_hash(0, &witness_script, value, $sighash_type)
                            .unwrap(),
                        $sighash
                            .parse::<SegwitV0Sighash>()
                            .unwrap(),
                    );
                }
            )*
        }
    }
    check_bip143_p2wsh_nested_in_p2sh! {
        // EcdsaSighashType::All tested above.
        bip143_p2wsh_nested_in_p2sh_sighash_none, None, "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36";
        bip143_p2wsh_nested_in_p2sh_sighash_single, Single, "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea";
        bip143_p2wsh_nested_in_p2sh_sighash_all_plus_anyonecanpay, AllPlusAnyoneCanPay, "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e";
        bip143_p2wsh_nested_in_p2sh_sighash_none_plus_anyonecanpay, NonePlusAnyoneCanPay, "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a";
        bip143_p2wsh_nested_in_p2sh_sighash_single_plus_anyonecanpay, SinglePlusAnyoneCanPay, "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b";
    }
}
