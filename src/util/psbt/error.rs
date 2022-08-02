// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;

use core::fmt;

use crate::blockdata::transaction::Transaction;
use crate::consensus::encode;
use crate::util::psbt::raw;

use crate::hashes;
use crate::util::bip32::ExtendedPubKey;
use crate::internal_macros::write_err;

/// Enum for marking psbt hash error.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PsbtHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}
/// Ways that a Partially Signed Transaction might fail.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
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
    ConsensusEncoding,
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
            Error::ConsensusEncoding => f.write_str("bitcoin consensus or BIP-174 encoding error"),
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
            | ConsensusEncoding => None,
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
    fn from(err: encode::Error) -> Self {
        match err {
            encode::Error::Psbt(err) => err,
            _ => Error::ConsensusEncoding,
        }
    }
}
