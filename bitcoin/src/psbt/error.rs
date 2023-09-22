// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use internals::write_err;

use crate::bip32::Xpub;
use crate::consensus::encode;
use crate::hash_types::Txid;
use crate::prelude::*;
use crate::psbt::{raw, FutureVersionError};
use crate::{hashes, io};

/// Enum for marking psbt hash error.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PsbtHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}
/// Ways that a Partially Signed Transaction might fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Magic bytes for a PSBT must be the ASCII for "psbt" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// Missing both the witness and non-witness utxo.
    MissingUtxo,
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator,
    /// Returned when output index is out of bounds in relation to the output in non-witness UTXO.
    PsbtUtxoOutOfbounds,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Future version of PSBT which can't be parsed by this library
    FutureVersion(FutureVersionError),
    /// The scriptSigs for the unsigned transaction must be empty.
    UnsignedTxHasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    UnsignedTxHasScriptWitnesses,
    /// A PSBTV0 must have an unsigned transaction.
    MustHaveUnsignedTx,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Attempting to combine with a PSBT describing a different unique identification.
    UnexpectedUniqueId {
        /// Expected
        expected: Box<Txid>,
        /// Actual
        actual: Box<Txid>,
    },
    /// Unable to parse as a standard sighash type.
    NonStandardSighashType(u32),
    /// Invalid hash when parsing slice.
    InvalidHash(hashes::FromSliceError),
    /// The pre-image must hash to the correponding psbt hash
    InvalidPreimageHashPair {
        /// Hash-type
        hash_type: PsbtHash,
        /// Pre-image
        preimage: Box<[u8]>,
        /// Hash value
        hash: Box<[u8]>,
    },
    /// Conflicting data during combine procedure:
    /// global extended public key has inconsistent key sources
    CombineInconsistentKeySources(Box<Xpub>),
    /// Serialization error in bitcoin consensus-encoded structures
    ConsensusEncoding(encode::Error),
    /// Negative fee
    NegativeFee,
    /// Integer overflow in fee calculation
    FeeOverflow,
    /// Parsing error indicating invalid public keys
    InvalidPublicKey(crate::crypto::key::Error),
    /// Parsing error indicating invalid secp256k1 public keys
    InvalidSecp256k1PublicKey(secp256k1::Error),
    /// Parsing error indicating invalid xonly public keys
    InvalidXOnlyPublicKey,
    /// Parsing error indicating invalid ECDSA signatures
    InvalidEcdsaSignature(crate::crypto::ecdsa::Error),
    /// Parsing error indicating invalid taproot signatures
    InvalidTaprootSignature(crate::crypto::taproot::SigFromSliceError),
    /// Parsing error indicating invalid control block
    InvalidControlBlock,
    /// Parsing error indicating invalid leaf version
    InvalidLeafVersion,
    /// Parsing error indicating a taproot error
    Taproot(&'static str),
    /// Taproot tree deserilaization error
    TapTree(crate::taproot::IncompleteBuilder),
    /// Error related to an xpub key
    XPubKey(&'static str),
    /// Error related to PSBT version
    Version(&'static str),
    /// PSBT data is not consumed entirely
    PartialDataConsumption,
    /// I/O error.
    Io(io::Error),

    // PsbtV0 field Errors
    /// Transaction Version is not allowed in PsbtV0
    TxVersionPresent,
    /// Fallback Locktime is not allowed in PsbtV0
    FallbackLocktimePresent,
    /// Transaction Modifiable flags are not allowed in PsbtV0
    TxModifiablePresent,
    /// Invalid Input
    InvalidInput,
    /// Invalid Output
    InvalidOutput,

    // PsbtV2 field Errors
    /// Transaction Version not present in PsbtV2 or invallid if present
    InvalidTxVersion,
    /// Unsigned Transaction is not allowed in PsbtV2
    UnsignedTxPresent,
    /// In a serialized psbtv2, input and output counts are required
    /// to be present in the global types section. On the other hand,
    /// they must be omitted in PsbtV0.
    InvalidInputOutputCounts,
    /// Computing Locktime error for Non-PsbtV0 indicating the
    /// required Locktime not present in the input.
    RequiredLocktimeNotPresent,
    /// Input can not be added to the PsbtV2.
    InputNotAddable(&'static str),
    /// Outputs can not be modified as `output_modifiable` flag is `false` in PsbtV2.
    OutputNotAddable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidMagic => f.write_str("invalid magic"),
            Error::MissingUtxo => f.write_str("UTXO information is not present in PSBT"),
            Error::InvalidSeparator => f.write_str("invalid separator"),
            Error::PsbtUtxoOutOfbounds =>
                f.write_str("output index is out of bounds of non witness script output array"),
            Error::InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            Error::InvalidProprietaryKey => {
                write!(f, "non-proprietary key type found when proprietary key was expected")
            }
            Error::DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            Error::FutureVersion(ref e) => write_err!(f, "unrecognized PSBT version"; e),
            Error::UnsignedTxHasScriptSigs =>
                f.write_str("the unsigned transaction has script sigs"),
            Error::UnsignedTxHasScriptWitnesses =>
                f.write_str("the unsigned transaction has script witnesses"),
            Error::MustHaveUnsignedTx =>
                f.write_str("partially signed transactions must have an unsigned transaction"),
            Error::NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Error::UnexpectedUniqueId { expected: ref e, actual: ref a } =>
                write!(f, "different unsigned transaction: expected {}, actual {}", e, a),
            Error::NonStandardSighashType(ref sht) => {
                write!(f, "non-standard sighash type: {}", sht)
            }
            Error::InvalidHash(ref e) => write_err!(f, "invalid hash when parsing slice"; e),
            Error::InvalidPreimageHashPair { ref preimage, ref hash, ref hash_type } => {
                // directly using debug forms of psbthash enums
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash)
            }
            Error::CombineInconsistentKeySources(ref s) => {
                write!(f, "combine conflict: {}", s)
            }
            Error::ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            Error::NegativeFee => f.write_str("PSBT has a negative fee which is not allowed"),
            Error::FeeOverflow => f.write_str("integer overflow in fee calculation"),
            Error::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Error::InvalidSecp256k1PublicKey(ref e) => {
                write_err!(f, "invalid secp256k1 public key"; e)
            }
            Error::InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            Error::InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            Error::InvalidTaprootSignature(ref e) => write_err!(f, "invalid taproot signature"; e),
            Error::InvalidControlBlock => f.write_str("invalid control block"),
            Error::InvalidLeafVersion => f.write_str("invalid leaf version"),
            Error::Taproot(s) => write!(f, "taproot error -  {}", s),
            Error::TapTree(ref e) => write_err!(f, "taproot tree error"; e),
            Error::XPubKey(s) => write!(f, "xpub key error -  {}", s),
            Error::Version(s) => write!(f, "version error {}", s),
            Error::PartialDataConsumption =>
                f.write_str("data not consumed entirely when explicitly deserializing"),
            Error::Io(ref e) => write_err!(f, "I/O error"; e),
            Error::TxVersionPresent => f.write_str("transaction version not allowed in PsbtV0"),
            Error::FallbackLocktimePresent =>
                f.write_str("fallback locktime not allowed in PsbtV0"),
            Error::TxModifiablePresent => f.write_str("TxModifiable not allowed in PsbtV0"),
            Error::InvalidTxVersion => f.write_str("transaction version is required in PsbtV2"),
            Error::UnsignedTxPresent => f.write_str("unsigned transaction not allowed in PsbtV2"),
            Error::InvalidInputOutputCounts => f.write_str("input and output counts are not valid"),
            Error::InvalidInput => f.write_str("input not valid"),
            Error::InvalidOutput => f.write_str("output not valid"),
            Error::RequiredLocktimeNotPresent =>
                f.write_str("required locktime not present in this Psbt input"),
            Error::InputNotAddable(s) => write!(f, "input can not be added - {}", s),
            Error::OutputNotAddable =>
                f.write_str("output can not be added as output_modifiable flag is false"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            InvalidHash(e) => Some(e),
            ConsensusEncoding(e) => Some(e),
            FutureVersion(e) => Some(e),
            Io(e) => Some(e),
            InvalidMagic
            | MissingUtxo
            | InvalidSeparator
            | PsbtUtxoOutOfbounds
            | InvalidKey(_)
            | InvalidProprietaryKey
            | DuplicateKey(_)
            | UnsignedTxHasScriptSigs
            | UnsignedTxHasScriptWitnesses
            | MustHaveUnsignedTx
            | NoMorePairs
            | &UnexpectedUniqueId { .. }
            | NonStandardSighashType(_)
            | InvalidPreimageHashPair { .. }
            | CombineInconsistentKeySources(_)
            | NegativeFee
            | FeeOverflow
            | InvalidPublicKey(_)
            | InvalidSecp256k1PublicKey(_)
            | InvalidXOnlyPublicKey
            | InvalidEcdsaSignature(_)
            | InvalidTaprootSignature(_)
            | InvalidControlBlock
            | InvalidLeafVersion
            | Taproot(_)
            | TapTree(_)
            | XPubKey(_)
            | Version(_)
            | PartialDataConsumption
            | TxVersionPresent
            | FallbackLocktimePresent
            | TxModifiablePresent
            | InvalidTxVersion
            | UnsignedTxPresent
            | InvalidInputOutputCounts
            | InvalidInput
            | InvalidOutput
            | RequiredLocktimeNotPresent
            | InputNotAddable(_)
            | OutputNotAddable => None,
        }
    }
}

impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::InvalidHash(e) }
}

impl From<FutureVersionError> for Error {
    fn from(err: FutureVersionError) -> Self { Error::FutureVersion(err) }
}

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self { Error::ConsensusEncoding(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::Io(e) }
}
