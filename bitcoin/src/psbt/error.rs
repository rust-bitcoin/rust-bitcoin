// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;

use core::fmt;

use bitcoin_internals::write_err;

use crate::blockdata::transaction::Transaction;
use crate::consensus::encode;
use crate::psbt::raw;

use crate::hashes;
use crate::io;
use crate::bip32::ExtendedPubKey;

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
    /// Parsing errors from bitcoin_hashes
    HashParse(hashes::Error),
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
    CombineInconsistentKeySources(Box<ExtendedPubKey>),
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
    InvalidTaprootSignature(crate::crypto::taproot::Error),
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidMagic => f.write_str("invalid magic"),
            Error::MissingUtxo => f.write_str("UTXO information is not present in PSBT"),
            Error::InvalidSeparator => f.write_str("invalid separator"),
            Error::PsbtUtxoOutOfbounds => f.write_str("output index is out of bounds of non witness script output array"),
            Error::InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            Error::InvalidProprietaryKey => write!(f, "non-proprietary key type found when proprietary key was expected"),
            Error::DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            Error::UnsignedTxHasScriptSigs => f.write_str("the unsigned transaction has script sigs"),
            Error::UnsignedTxHasScriptWitnesses => f.write_str("the unsigned transaction has script witnesses"),
            Error::MustHaveUnsignedTx => {
                f.write_str("partially signed transactions must have an unsigned transaction")
            }
            Error::NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Error::UnexpectedUnsignedTx { expected: ref e, actual: ref a } => write!(f, "different unsigned transaction: expected {}, actual {}", e.txid(), a.txid()),
            Error::NonStandardSighashType(ref sht) => write!(f, "non-standard sighash type: {}", sht),
            Error::HashParse(ref e) => write_err!(f, "hash parse error"; e),
            Error::InvalidPreimageHashPair{ref preimage, ref hash, ref hash_type} => {
                // directly using debug forms of psbthash enums
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash )
            },
            Error::CombineInconsistentKeySources(ref s) => { write!(f, "combine conflict: {}", s) },
            Error::ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            Error::NegativeFee => f.write_str("PSBT has a negative fee which is not allowed"),
            Error::FeeOverflow => f.write_str("integer overflow in fee calculation"),
            Error::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Error::InvalidSecp256k1PublicKey(ref e) => write_err!(f, "invalid secp256k1 public key"; e),
            Error::InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            Error::InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            Error::InvalidTaprootSignature(ref e) => write_err!(f, "invalid taproot signature"; e),
            Error::InvalidControlBlock => f.write_str("invalid control block"),
            Error::InvalidLeafVersion => f.write_str("invalid leaf version"),
            Error::Taproot(s) => write!(f, "taproot error -  {}", s),
            Error::TapTree(ref e) => write_err!(f, "taproot tree error"; e),
            Error::XPubKey(s) => write!(f, "xpub key error -  {}", s),
            Error::Version(s) => write!(f, "version error {}", s),
            Error::PartialDataConsumption => f.write_str("data not consumed entirely when explicitly deserializing"),
            Error::Io(ref e) => write_err!(f, "I/O error"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            HashParse(e) => Some(e),
            ConsensusEncoding(e) => Some(e),
            Io(e) => Some(e),
            | InvalidMagic
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
            | UnexpectedUnsignedTx { .. }
            | NonStandardSighashType(_)
            | InvalidPreimageHashPair{ .. }
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
            | PartialDataConsumption=> None,
        }
    }
}

#[doc(hidden)]
impl From<hashes::Error> for Error {
    fn from(e: hashes::Error) -> Error {
        Error::HashParse(e)
    }
}

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self {
        Error::ConsensusEncoding(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
