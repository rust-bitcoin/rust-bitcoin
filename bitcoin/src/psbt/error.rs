// SPDX-License-Identifier: CC0-1.0

use core::convert::Infallible;
use core::fmt;

use internals::error::ParseErrorContext;
use internals::write_err;

use crate::bip32::Xpub;
use crate::consensus::encode;
use crate::prelude::Box;
use crate::psbt::raw;
use crate::transaction::Transaction;

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
    /// Parsing error indicating invalid public keys
    InvalidPublicKey(crate::crypto::key::FromSliceError),
    /// Parsing error indicating invalid secp256k1 public keys
    InvalidSecp256k1PublicKey(secp256k1::Error),
    /// Parsing error indicating invalid xonly public keys
    InvalidXOnlyPublicKey,
    /// Parsing error indicating invalid ECDSA signatures
    InvalidEcdsaSignature(crate::crypto::ecdsa::DecodeError),
    /// Parsing error indicating invalid Taproot signatures
    InvalidTaprootSignature(crate::crypto::taproot::SigFromSliceError),
    /// Parsing error indicating invalid control block
    InvalidControlBlock,
    /// Parsing error indicating invalid leaf version
    InvalidLeafVersion,
    /// Parsing error indicating a Taproot error
    Taproot(&'static str),
    /// Taproot tree deserialization error
    TapTree(crate::taproot::IncompleteBuilderError),
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

// Helper struct to display expecting messages for delegated errors
struct ExpectingDisplay<D: fmt::Display>(D);
impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ParseErrorContext for Error {
    fn expecting(&self) -> Box<dyn fmt::Display + '_> {
        use Error::*;
        match self {
            InvalidMagic => Box::new("magic bytes \"psbt\" (0x70736274)"),
            MissingUtxo => Box::new("either a non-witness or witness UTXO for each input"),
            InvalidSeparator => Box::new("the separator byte 0xff"),
            PsbtUtxoOutOfbounds => Box::new("an output index within the bounds of the UTXO transaction"),
            InvalidKey(_) => Box::new("a valid PSBT key"),
            InvalidProprietaryKey => Box::new("a proprietary key"),
            DuplicateKey(_) => Box::new("unique keys within a PSBT map"),
            UnsignedTxHasScriptSigs => Box::new("an unsigned transaction with no scriptSigs"),
            UnsignedTxHasScriptWitnesses => Box::new("an unsigned transaction with no scriptWitnesses"),
            MustHaveUnsignedTx => Box::new("an unsigned transaction global field"),
            NoMorePairs => Box::new("end of key-value pairs (0x00 byte)"),
            UnexpectedUnsignedTx { .. } => Box::new("a PSBT for the same unsigned transaction"),
            NonStandardSighashType(_) => Box::new("a standard sighash type"),
            InvalidHash(_) => Box::new("a valid hash digest"),
            InvalidPreimageHashPair { .. } => Box::new("a preimage matching the provided hash"),
            CombineInconsistentKeySources(_) => Box::new("consistent key sources for the global xpub"),
            ConsensusEncoding(_) => Box::new("valid data for consensus serialization"),
            ConsensusDeserialize(_) => Box::new("valid consensus data that is fully consumed"),
            ConsensusParse(e) => e.expecting(),
            NegativeFee => Box::new("a non-negative fee"),
            FeeOverflow => Box::new("inputs and outputs resulting in a valid fee calculation"),
            InvalidPublicKey(_) => Box::new("a valid public key"),
            InvalidSecp256k1PublicKey(_) => Box::new("a valid secp256k1 public key"),
            InvalidXOnlyPublicKey => Box::new("a valid x-only public key"),
            InvalidEcdsaSignature(_) => Box::new("a valid ECDSA signature"),
            InvalidTaprootSignature(_) => Box::new("a valid Taproot Schnorr signature"),
            InvalidControlBlock => Box::new("a valid Taproot control block"),
            InvalidLeafVersion => Box::new("a valid Taproot leaf version"),
            Taproot(_) => Box::new("valid Taproot script/key path data"),
            TapTree(_) => Box::new("a valid Taproot tree structure"),
            XPubKey(_) => Box::new("valid extended public key data"),
            Version(_) => Box::new("a supported PSBT version"),
            PartialDataConsumption => Box::new("fully consumed PSBT data"),
            Io(_) => Box::new("successful I/O"),
        }
    }

    fn help(&self) -> Option<Box<dyn fmt::Display + '_>> {
        use Error::*;
        match self {
            InvalidMagic => Some(Box::new("The PSBT should start with the bytes 0x70, 0x73, 0x62, 0x74.")),
            InvalidSeparator => Some(Box::new("PSBT key-value pairs within a map must end with a 0x00 separator byte.")),
            DuplicateKey(key) => {
                struct HelpDisplay<'a>(&'a raw::Key);
                impl fmt::Display for HelpDisplay<'_> {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "Duplicate key found: Type=0x{:02x}, Key={:?}", self.0.type_value, self.0.key_data)
                    }
                }
                Some(Box::new(HelpDisplay(key)))
            },
            NoMorePairs => Some(Box::new("Expected more key-value pairs but found the map separator (0x00).")),
            ConsensusParse(e) => e.help(),
            NonStandardSighashType(sht) => {
                struct HelpDisplay(u32);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "Sighash type 0x{:08x} is not standard.", self.0)
                    }
                }
                Some(Box::new(HelpDisplay(*sht)))
            },
            InvalidPublicKey(_) => Some(Box::new("Public key data is not valid (e.g., wrong length or invalid point).")),
            InvalidSecp256k1PublicKey(_) => Some(Box::new("Public key is not a valid secp256k1 point.")),
            InvalidXOnlyPublicKey => Some(Box::new("Public key is not a valid x-only public key.")),
            InvalidEcdsaSignature(_) => Some(Box::new("ECDSA signature is not valid (e.g., wrong format or invalid values).")),
            InvalidTaprootSignature(_) => Some(Box::new("Taproot signature is not valid (e.g., wrong length or invalid format).")),
            InvalidControlBlock => Some(Box::new("Taproot control block is invalid (e.g., wrong size, invalid leaf version, or invalid proof).")),
            InvalidLeafVersion => Some(Box::new("Taproot leaf version byte is invalid (must be even, not 0x50).")),
            Version(s) => {
                struct HelpDisplay(&'static str);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "PSBT version error: {}", self.0)
                    }
                }
                Some(Box::new(HelpDisplay(s)))
            },
            PartialDataConsumption => Some(Box::new("Deserialization did not consume all provided PSBT data.")),
            _ => None,
        }
    }

    fn note(&self) -> Option<&'static str> {
        use Error::*;
        match self {
            InvalidMagic | InvalidSeparator | DuplicateKey(_) | NoMorePairs | Version(_) => Some("See BIP174 for PSBT structure details."),
            NonStandardSighashType(_) => Some("See BIP143 and BIP341 for standard sighash types."),
            ConsensusParse(e) => e.note(),
            InvalidPublicKey(_) | InvalidSecp256k1PublicKey(_) | InvalidXOnlyPublicKey => Some("Keys must conform to secp256k1 standards."),
            InvalidEcdsaSignature(_) => Some("ECDSA signatures must be DER encoded."),
            InvalidTaprootSignature(_) => Some("Taproot signatures use Schnorr format (BIP340)."),
            InvalidControlBlock | InvalidLeafVersion | Taproot(_) | TapTree(_) => Some("See BIP341 and BIP342 for Taproot rules."),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            InvalidMagic => f.write_str("invalid magic"),
            MissingUtxo => f.write_str("UTXO information is not present in PSBT"),
            InvalidSeparator => f.write_str("invalid separator"),
            PsbtUtxoOutOfbounds =>
                f.write_str("output index is out of bounds of non witness script output array"),
            InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            UnsignedTxHasScriptSigs => f.write_str("the unsigned transaction has script sigs"),
            UnsignedTxHasScriptWitnesses =>
                f.write_str("the unsigned transaction has script witnesses"),
            MustHaveUnsignedTx =>
                f.write_str("partially signed transactions must have an unsigned transaction"),
            NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            UnexpectedUnsignedTx { expected: ref e, actual: ref a } => write!(
                f,
                "different unsigned transaction: expected {}, actual {}",
                e.compute_txid(),
                a.compute_txid()
            ),
            NonStandardSighashType(ref sht) => write!(f, "non-standard sighash type: {}", sht),
            InvalidHash(ref e) => write_err!(f, "invalid hash when parsing slice"; e),
            InvalidPreimageHashPair { ref preimage, ref hash, ref hash_type } => {
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash)
            }
            CombineInconsistentKeySources(ref s) => {
                write!(f, "combine conflict: {}", s)
            }
            ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            ConsensusDeserialize(ref e) =>
                write_err!(f, "bitcoin consensus deserializaton error"; e),
            ConsensusParse(ref e) =>
                write_err!(f, "error parsing bitcoin consensus encoded object"; e),
            NegativeFee => f.write_str("PSBT has a negative fee which is not allowed"),
            FeeOverflow => f.write_str("integer overflow in fee calculation"),
            InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            InvalidSecp256k1PublicKey(ref e) => write_err!(f, "invalid secp256k1 public key"; e),
            InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            InvalidTaprootSignature(ref e) => write_err!(f, "invalid Taproot signature"; e),
            InvalidControlBlock => f.write_str("invalid control block"),
            InvalidLeafVersion => f.write_str("invalid leaf version"),
            Taproot(s) => write!(f, "Taproot error -  {}", s),
            TapTree(ref e) => write_err!(f, "Taproot tree error"; e),
            XPubKey(s) => write!(f, "xpub key error -  {}", s),
            Version(s) => write!(f, "version error {}", s),
            PartialDataConsumption =>
                f.write_str("data not consumed entirely when explicitly deserializing"),
            Io(ref e) => write_err!(f, "I/O error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            InvalidHash(ref e) => Some(e),
            ConsensusEncoding(ref e) => Some(e),
            ConsensusDeserialize(ref e) => Some(e),
            ConsensusParse(ref e) => Some(e),
            Io(ref e) => Some(e),
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
            | UnexpectedUnsignedTx { .. }
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
            | PartialDataConsumption => None,
        }
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(e: core::array::TryFromSliceError) -> Error { Error::InvalidHash(e) }
}

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self { Error::ConsensusEncoding(e) }
}

impl From<encode::DeserializeError> for Error {
    fn from(e: encode::DeserializeError) -> Self { Error::ConsensusDeserialize(e) }
}

impl From<encode::ParseError> for Error {
    fn from(e: encode::ParseError) -> Self { Error::ConsensusParse(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::Io(e) }
}
