// SPDX-License-Identifier: CC0-1.0

use core::convert::Infallible;
use core::fmt;

use internals::write_err;

use crate::bip32::Xpub;
use crate::consensus::encode;
use crate::prelude::Box;
use crate::psbt::raw;
use crate::{ecdsa, key, taproot, OutPoint, Transaction, Txid};

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
    /// The scriptSigs for the unsigned transaction must be empty.
    UnsignedTxHasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    UnsignedTxHasScriptWitnesses,
    /// A PSBT must have an unsigned transaction.
    MustHaveUnsignedTx,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Attempting to combine with a PSBT describing a different unsigned
    /// transaction.
    UnexpectedUnsignedTx {
        /// Expected
        expected: Box<Transaction>,
        /// Actual
        actual: Box<Transaction>,
    },
    /// Unable to parse as a standard sighash type.
    NonStandardSighashType(u32),
    /// Invalid hash when parsing slice.
    InvalidHash(core::array::TryFromSliceError),
    /// The pre-image must hash to the corresponding psbt hash
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
    /// Deserialization error in bitcoin consensus-encoded structures.
    ConsensusDeserialize(encode::DeserializeError),
    /// Error parsing bitcoin consensus-encoded object.
    ConsensusParse(encode::ParseError),
    /// Negative fee
    NegativeFee,
    /// Integer overflow in fee calculation
    FeeOverflow,
    /// Non-witness UTXO (which is a complete transaction) has `Txid` that
    /// does not match the transaction input.
    IncorrectNonWitnessUtxo {
        /// The index of the input in question.
        index: usize,
        /// The outpoint of the input, as it appears in the unsigned transaction.
        input_outpoint: OutPoint,
        /// The [`Txid`] of the non-witness UTXO.
        non_witness_utxo_txid: Txid,
    },
    /// Non-witness UTXO does not have enough outputs for the `vout` specified
    /// in the transaction input.
    NonWitnessUtxoOutOfBounds {
        /// The index of the input in question.
        index: usize,
        /// The vout of the input, as it appears in the unsigned transaction.
        vout: u32,
        /// The number of outputs in the non-witness UTXO.
        non_witness_utxo_output_count: usize,
    },
    /// Parsing error indicating invalid public keys
    InvalidPublicKey(key::FromSliceError),
    /// Parsing error indicating invalid secp256k1 public keys
    InvalidSecp256k1PublicKey(secp256k1::Error),
    /// Parsing error indicating invalid xonly public keys
    InvalidXOnlyPublicKey,
    /// Parsing error indicating invalid ECDSA signatures
    InvalidEcdsaSignature(ecdsa::DecodeError),
    /// Parsing error indicating invalid Taproot signatures
    InvalidTaprootSignature(taproot::SigFromSliceError),
    /// Parsing error indicating invalid control block
    InvalidControlBlock,
    /// Parsing error indicating invalid leaf version
    InvalidLeafVersion,
    /// Parsing error indicating a Taproot error
    Taproot(&'static str),
    /// Taproot tree deserialization error
    TapTree(taproot::IncompleteBuilderError),
    /// Error related to an xpub key
    XPubKey(&'static str),
    /// Error related to PSBT version
    Version(&'static str),
    /// PSBT data is not consumed entirely
    PartialDataConsumption,
    /// I/O error.
    Io(io::Error),
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid magic"),
            Self::MissingUtxo => f.write_str("UTXO information is not present in PSBT"),
            Self::InvalidSeparator => f.write_str("invalid separator"),
            Self::PsbtUtxoOutOfbounds =>
                f.write_str("output index is out of bounds of non witness script output array"),
            Self::InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            Self::InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            Self::DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            Self::UnsignedTxHasScriptSigs =>
                f.write_str("the unsigned transaction has script sigs"),
            Self::UnsignedTxHasScriptWitnesses =>
                f.write_str("the unsigned transaction has script witnesses"),
            Self::MustHaveUnsignedTx =>
                f.write_str("partially signed transactions must have an unsigned transaction"),
            Self::NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Self::UnexpectedUnsignedTx { expected: ref e, actual: ref a } => write!(
                f,
                "different unsigned transaction: expected {}, actual {}",
                e.compute_txid(),
                a.compute_txid()
            ),
            Self::NonStandardSighashType(ref sht) =>
                write!(f, "non-standard sighash type: {}", sht),
            Self::InvalidHash(ref e) => write_err!(f, "invalid hash when parsing slice"; e),
            Self::InvalidPreimageHashPair { ref preimage, ref hash, ref hash_type } => {
                // directly using debug forms of psbthash enums
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash)
            }
            Self::CombineInconsistentKeySources(ref s) => {
                write!(f, "combine conflict: {}", s)
            }
            Self::ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            Self::ConsensusDeserialize(ref e) =>
                write_err!(f, "bitcoin consensus deserialization error"; e),
            Self::ConsensusParse(ref e) =>
                write_err!(f, "error parsing bitcoin consensus encoded object"; e),
            Self::NegativeFee => f.write_str("PSBT has a negative fee which is not allowed"),
            Self::FeeOverflow => f.write_str("integer overflow in fee calculation"),
            Self::IncorrectNonWitnessUtxo { index, input_outpoint, non_witness_utxo_txid } => {
                write!(
                    f,
                    "non-witness utxo txid is {}, which does not match input {}'s outpoint {}",
                    non_witness_utxo_txid, index, input_outpoint
                )
            }
            Self::NonWitnessUtxoOutOfBounds { index, vout, non_witness_utxo_output_count } => {
                write!(
                    f,
                    "input {} references vout {}, but non-witness UTXO only has {} outputs",
                    index, vout, non_witness_utxo_output_count
                )
            }
            Self::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Self::InvalidSecp256k1PublicKey(ref e) =>
                write_err!(f, "invalid secp256k1 public key"; e),
            Self::InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            Self::InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            Self::InvalidTaprootSignature(ref e) => write_err!(f, "invalid Taproot signature"; e),
            Self::InvalidControlBlock => f.write_str("invalid control block"),
            Self::InvalidLeafVersion => f.write_str("invalid leaf version"),
            Self::Taproot(s) => write!(f, "Taproot error -  {}", s),
            Self::TapTree(ref e) => write_err!(f, "Taproot tree error"; e),
            Self::XPubKey(s) => write!(f, "xpub key error -  {}", s),
            Self::Version(s) => write!(f, "version error {}", s),
            Self::PartialDataConsumption =>
                f.write_str("data not consumed entirely when explicitly deserializing"),
            Self::Io(ref e) => write_err!(f, "I/O error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHash(ref e) => Some(e),
            Self::ConsensusEncoding(ref e) => Some(e),
            Self::ConsensusDeserialize(ref e) => Some(e),
            Self::ConsensusParse(ref e) => Some(e),
            Self::Io(ref e) => Some(e),
            Self::InvalidMagic
            | Self::MissingUtxo
            | Self::InvalidSeparator
            | Self::PsbtUtxoOutOfbounds
            | Self::InvalidKey(_)
            | Self::InvalidProprietaryKey
            | Self::DuplicateKey(_)
            | Self::UnsignedTxHasScriptSigs
            | Self::UnsignedTxHasScriptWitnesses
            | Self::MustHaveUnsignedTx
            | Self::NoMorePairs
            | Self::UnexpectedUnsignedTx { .. }
            | Self::NonStandardSighashType(_)
            | Self::InvalidPreimageHashPair { .. }
            | Self::CombineInconsistentKeySources(_)
            | Self::NegativeFee
            | Self::FeeOverflow
            | Self::IncorrectNonWitnessUtxo { .. }
            | Self::NonWitnessUtxoOutOfBounds { .. }
            | Self::InvalidPublicKey(_)
            | Self::InvalidSecp256k1PublicKey(_)
            | Self::InvalidXOnlyPublicKey
            | Self::InvalidEcdsaSignature(_)
            | Self::InvalidTaprootSignature(_)
            | Self::InvalidControlBlock
            | Self::InvalidLeafVersion
            | Self::Taproot(_)
            | Self::TapTree(_)
            | Self::XPubKey(_)
            | Self::Version(_)
            | Self::PartialDataConsumption => None,
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(e: core::array::TryFromSliceError) -> Self { Self::InvalidHash(e) }
}

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self { Self::ConsensusEncoding(e) }
}

impl From<encode::DeserializeError> for Error {
    fn from(e: encode::DeserializeError) -> Self { Self::ConsensusDeserialize(e) }
}

impl From<encode::ParseError> for Error {
    fn from(e: encode::ParseError) -> Self { Self::ConsensusParse(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
