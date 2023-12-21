//! Support for known script templates.
//!
//! While Bitcoin scripts support wide variety of conditions, there's a handful of known, popular
//! templates used. Those are mainly related to simple direct payments or wrappers for scripts
//! which make them easier to transfer.
//!
//! This module provides two main types: [`Template`] and [`RawTemplate`]. These represent all
//! popular known templates (at the time of writing the library). The main difference between them
//! is that `Template` is validated (to the degree it can be), while `RawTemplate` is not (apart
//! from lengths.
//!
//! While most users should use [`Template`], [`RawTemplate`] can be used in advanced scenarios
//! such as analysis of how many templates in the chain are valid. Notably, invalid templates are
//! unspendable.

use alloc::boxed::Box;
use core::fmt;
use core::borrow::Borrow;
use core::ops::Deref;
use crate::{Script, PublicKey, CompressedPublicKey, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash, WitnessVersion, WitnessProgram, XOnlyPublicKey};
use crate::key::TweakedPublicKey;
use hashes::Hash;
use internals::array_vec::ArrayVec;

/// A known script template with basic validation of the underlying data.
///
/// The public keys in this template are validated, however, the hashes cannot be without knowing
/// the preimage which we often don't know.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Template {
    /// Pay to public key.
    P2Pk(PublicKey),

    /// Pay to public key hash.
    P2Pkh(PubkeyHash),

    /// Pay to script hash.
    P2Sh(ScriptHash),

    /// A witness script.
    ///
    /// Refer to [`SegWitTemplate`] for getting specific version and witness program.
    SegWit(SegWitTemplate),

    /// An unspendable template containing data.
    OpReturn(Box<[u8]>),
}

impl Template {
    /// Constructs `P2Pkh` template using the public key.
    ///
    /// This is a convenience function which hashes the parameter.
    pub fn p2pkh(pubkey: PublicKey) -> Self {
        Template::P2Pkh(pubkey.into())
    }

    /// Constructs `P2Sh` template using the script.
    ///
    /// This is a convenience function which hashes the parameter.
    pub fn p2sh(script: &Script) -> Self {
        Template::P2Sh(script.into())
    }

    /// Constructs `P2Wpkh` template using the public key.
    ///
    /// This is a convenience function which hashes the parameter.
    ///
    /// # Panics
    ///
    /// If `pubkey` is uncompressed.
    #[track_caller]
    pub fn p2wpkh(pubkey: CompressedPublicKey) -> Self {
        Template::SegWit(SegWitTemplate::P2WPkh(pubkey.wpubkey_hash()))
    }

    /// Constructs `P2WSh` template using the script.
    ///
    /// This is a convenience function which hashes the parameter.
    pub fn p2wsh(script: &Script) -> Self {
        Template::SegWit(SegWitTemplate::P2WSh(script.into()))
    }

    ///  Returns `true` if this is a pay-to-public-key.
    pub const fn is_p2pk(&self) -> bool {
        matches!(self, Template::P2Pk(_))
    }

    ///  Returns `true` if this is a compressed pay-to-public-key.
    pub const fn is_compressed_p2pk(&self) -> bool {
        matches!(self, Template::P2Pk(key) if key.compressed)
    }

    ///  Returns `true` if this is a uncompressed pay-to-public-key.
    pub const fn is_uncompressed_p2pk(&self) -> bool {
        matches!(self, Template::P2Pk(key) if !key.compressed)
    }

    ///  Returns `true` if this is a pay-to-public-key-hash.
    pub const fn is_p2pkh(&self) -> bool {
        matches!(self, Template::P2Pkh(_))
    }

    ///  Returns `true` if this is a pay-to-script-hash.
    pub const fn is_p2sh(&self) -> bool {
        matches!(self, Template::P2Sh(_))
    }

    ///  Returns `true` if this is a segwit template.
    pub const fn is_segwit(&self) -> bool {
        matches!(self, Template::P2Sh(_))
    }

    ///  Returns `true` if this is a pay-to-witness-public-key-hash.
    pub const fn is_p2wpkh(&self) -> bool {
        matches!(self, Template::SegWit(SegWitTemplate::P2WPkh(_)))
    }

    ///  Returns `true` if this is a pay-to-witness-script-hash.
    pub const fn is_p2wsh(&self) -> bool {
        matches!(self, Template::SegWit(SegWitTemplate::P2WSh(_)))
    }

    ///  Returns `true` if this is a pay-to-taproot.
    pub const fn is_p2tr(&self) -> bool {
        matches!(self, Template::SegWit(SegWitTemplate::P2Tr(_)))
    }

    /// Returns a valid template which the `script` matches (if any).
    pub fn from_script(script: &Script) -> Option<Self> {
        script.template()
    }
    /// Converts `self` to `RawTemplate` and passes it to a closure.
    ///
    /// The closure bypasses borrow error that would occur if we attempted to convert these using
    /// `From` or normal function.
    pub fn with_raw<R, F: FnOnce(RawTemplate) -> R>(&self, f: F) -> R {
        match self {
            Template::P2Pk(pubkey) => PubkeyBytes::with_pubkey(pubkey, |bytes| f(RawTemplate::P2Pk(bytes))),
            Template::P2Pkh(hash) => f(RawTemplate::P2Pkh(hash.as_byte_array())),
            Template::P2Sh(hash) => f(RawTemplate::P2Sh(hash.as_byte_array())),
            Template::SegWit(SegWitTemplate::P2WPkh(hash)) => f(RawTemplate::SegWit(RawSegWitTemplate::P2WPkh(hash.as_byte_array()))),
            Template::SegWit(SegWitTemplate::P2WSh(hash)) => f(RawTemplate::SegWit(RawSegWitTemplate::P2WSh(hash.as_byte_array()))),
            Template::SegWit(SegWitTemplate::P2Tr(pubkey)) => f(RawTemplate::SegWit(RawSegWitTemplate::P2Tr(&pubkey.serialize()))),
            Template::SegWit(SegWitTemplate::UnknownVersionDoNotUse(Private(program))) => {
                let mut buf = ArrayVec::<_, 40>::new();
                buf.push(program.version().to_opcode().to_u8());
                buf.extend_from_slice(program.program().as_ref());
                f(RawTemplate::SegWit(RawSegWitTemplate::UnknownVersionDoNotUse(Private(Script::from_bytes(&buf)))))
            },
            Template::OpReturn(bytes) => f(RawTemplate::OpReturn(&bytes))
        }
    }
}

impl TryFrom<RawTemplate<'_>> for Template {
    type Error = TemplateError;

    fn try_from(template: RawTemplate<'_>) -> Result<Self, Self::Error> {
        match template {
            RawTemplate::P2Pk(bytes) => Ok(Template::P2Pk(bytes.to_pubkey()?)),
            RawTemplate::P2Pkh(bytes) => Ok(Template::P2Pkh(PubkeyHash::from_byte_array(*bytes))),
            RawTemplate::P2Sh(bytes) => Ok(Template::P2Sh(ScriptHash::from_byte_array(*bytes))),
            RawTemplate::SegWit(segwit) => Ok(Template::SegWit(segwit.try_into()?)),
            RawTemplate::OpReturn(bytes) => Ok(Template::OpReturn(bytes.into())),
        }
    }
}

/// A validated pay-to-witness-something script template.
///
/// Along with the visible variants, this contains a trick which allows converting this into
/// `WitnessProgram` even when an unknown version is used.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum SegWitTemplate {
    /// Pay to witness public key hash.
    P2WPkh(WPubkeyHash),

    /// Pay to witness script hash.
    P2WSh(WScriptHash),

    /// Pay to taproot.
    P2Tr(TweakedPublicKey),

    /// DO NOT USE! Use [`into_witness_program`](Self::into_witness_program) if needed.
    ///
    /// This is future-proofing to be able to store data for unknown versions while still making it
    /// possible to remove the variant and make the enum not non-exhaustive if one day all 16
    /// versions get defined.
    #[doc(hidden)]
    UnknownVersionDoNotUse(Private<WitnessProgram>),
}

impl SegWitTemplate {
    /// Converts this template into `WitnessProgram`.
    ///
    /// Notably, if this enum contains an unknown version this still returns a valid value.
    pub fn into_witness_program(self) -> WitnessProgram {
        match self {
            SegWitTemplate::P2WPkh(hash) => WitnessProgram::p2wpkh(hash),
            SegWitTemplate::P2WSh(hash) => WitnessProgram::p2wsh(hash),
            SegWitTemplate::P2Tr(key) => WitnessProgram::p2tr_tweaked(key),
            SegWitTemplate::UnknownVersionDoNotUse(Private(program)) => program,
        }
    }

    ///  Returns `true` if this is a pay-to-witness-public-key-hash.
    pub const fn is_p2wpkh(&self) -> bool {
        matches!(self, SegWitTemplate::P2WPkh(_))
    }

    ///  Returns `true` if this is a pay-to-witness-script-hash.
    pub const fn is_p2wsh(&self) -> bool {
        matches!(self, SegWitTemplate::P2WSh(_))
    }

    ///  Returns `true` if this is a pay-to-taproot.
    pub const fn is_p2tr(&self) -> bool {
        matches!(self, SegWitTemplate::P2Tr(_))
    }
}

impl<'a> TryFrom<RawSegWitTemplate<'a>> for SegWitTemplate {
    type Error = SegWitError;

    fn try_from(value: RawSegWitTemplate<'a>) -> Result<Self, Self::Error> {
        Ok(match value {
            RawSegWitTemplate::P2WPkh(wpkh) => SegWitTemplate::P2WPkh(WPubkeyHash::from_byte_array(*wpkh)),
            RawSegWitTemplate::P2WSh(wsh) => SegWitTemplate::P2WSh(WScriptHash::from_byte_array(*wsh)),
            RawSegWitTemplate::P2Tr(pk) => {
                let pk = XOnlyPublicKey::from_slice(pk).map_err(SegWitError::P2Tr)?;
                // CORRECTNESS: the keys in the script are always tweaked.
                SegWitTemplate::P2Tr(TweakedPublicKey::dangerous_assume_tweaked(pk))
            },
            RawSegWitTemplate::UnknownVersionDoNotUse(Private(script)) => {
                let version = script.witness_version().unwrap();
                let program = &script.as_bytes()[2..];
                let program = WitnessProgram::new(version, program).unwrap();
                SegWitTemplate::UnknownVersionDoNotUse(Private(program))
            },
        })
    }
}

/// Error encountered when validating segwit script template.
pub enum SegWitError {
    /// Error converting P2TR template.
    P2Tr(secp256k1::Error),
}

/// Error when converting `RawTemplate` into `Template`.
#[non_exhaustive]
pub enum TemplateError {
    /// Error converting P2PK template.
    P2Pk(crate::key::Error),
    /// Error converting a segwit template.
    SegWit(SegWitError),
}

impl From<crate::key::Error> for TemplateError {
    fn from(value: crate::key::Error) -> Self {
        TemplateError::P2Pk(value)
    }
}

impl From<SegWitError> for TemplateError {
    fn from(value: SegWitError) -> Self {
        TemplateError::SegWit(value)
    }
}

/// A known script template with no validation of the underlying data.
///
/// The bytes in each variant refer to their respective payload.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RawTemplate<'a> {
    /// Pay to public key.
    P2Pk(PubkeyBytes<'a>),

    /// Pay to public key hash.
    P2Pkh(&'a [u8; 20]),

    /// Pay to script hash.
    P2Sh(&'a [u8; 20]),

    /// A pay to witness something template.
    SegWit(RawSegWitTemplate<'a>),

    /// An unspendable template containing data.
    OpReturn(&'a [u8]),
}

impl<'a> RawTemplate<'a> {
    /// Constructs `RawTemplate` with `P2Pk(PubkeyBytes::Compressed(bytes))`.
    ///
    /// This is a convenience constructor so that you don't have to import [`PubkeyBytes`].
    pub const fn p2pk_from_compressed(bytes: &'a [u8; 33]) -> Self {
        RawTemplate::P2Pk(PubkeyBytes::Compressed(bytes))
    }

    /// Constructs `RawTemplate` with `P2Pk(PubkeyBytes::Uncompressed(bytes))`.
    ///
    /// This is a convenience constructor so that you don't have to import [`PubkeyBytes`].
    pub const fn p2pk_from_uncompressed(bytes: &'a [u8; 65]) -> Self {
        RawTemplate::P2Pk(PubkeyBytes::Uncompressed(bytes))
    }

    /// Constructs `RawTemplate` with `P2WPkh(RawSegWitTemplate::P2WPkh(bytes))`.
    ///
    /// This is a convenience constructor so that you don't have to import [`RawSegWitTemplate`].
    pub const fn p2wpkh(bytes: &'a [u8; 20]) -> Self {
        RawTemplate::SegWit(RawSegWitTemplate::P2WPkh(bytes))
    }

    /// Constructs `RawTemplate` with `P2WSh(RawSegWitTemplate::P2Sh(bytes))`.
    ///
    /// This is a convenience constructor so that you don't have to import [`RawSegWitTemplate`].
    pub const fn p2wsh(bytes: &'a [u8; 32]) -> Self {
        RawTemplate::SegWit(RawSegWitTemplate::P2WSh(bytes))
    }

    /// Constructs `RawTemplate` with `P2WTr(RawSegWitTemplate::P2Tr(bytes))`.
    ///
    /// This is a convenience constructor so that you don't have to import [`RawSegWitTemplate`].
    pub const fn p2tr(bytes: &'a [u8; 32]) -> Self {
        RawTemplate::SegWit(RawSegWitTemplate::P2Tr(bytes))
    }

    ///  Returns `true` if this is a pay-to-public-key.
    pub const fn is_p2pk(&self) -> bool {
        matches!(self, RawTemplate::P2Pk(_))
    }

    ///  Returns `true` if this is a compressed pay-to-public-key.
    pub const fn is_compressed_p2pk(&self) -> bool {
        matches!(self, RawTemplate::P2Pk(PubkeyBytes::Compressed(_)))
    }

    ///  Returns `true` if this is a uncompressed pay-to-public-key.
    pub const fn is_uncompressed_p2pk(&self) -> bool {
        matches!(self, RawTemplate::P2Pk(PubkeyBytes::Uncompressed(_)))
    }

    ///  Returns `true` if this is a pay-to-public-key-hash.
    pub const fn is_p2pkh(&self) -> bool {
        matches!(self, RawTemplate::P2Pkh(_))
    }

    ///  Returns `true` if this is a pay-to-script-hash.
    pub const fn is_p2sh(&self) -> bool {
        matches!(self, RawTemplate::P2Sh(_))
    }

    ///  Returns `true` if this is a pay-to-witness-public-key-hash.
    pub const fn is_p2wpkh(&self) -> bool {
        matches!(self, RawTemplate::SegWit(segwit) if segwit.is_p2wpkh())
    }

    ///  Returns `true` if this is a pay-to-witness-script-hash.
    pub const fn is_p2wsh(&self) -> bool {
        matches!(self, RawTemplate::SegWit(segwit) if segwit.is_p2wsh())
    }

    ///  Returns `true` if this is a pay-to-taproot.
    pub const fn is_p2tr(&self) -> bool {
        matches!(self, RawTemplate::SegWit(segwit) if segwit.is_p2tr())
    }

    /// Returns a template which the `script` matches (if any).
    pub fn from_script(script: &'a Script) -> Option<Self> {
        script.raw_template()
    }

    /// Helper for the crate.
    ///
    /// # Panics
    ///
    /// If script is not a witness program.
    #[track_caller]
    pub(crate) fn raw_segwit_script_pubkey(script: &'a Script) -> Option<Self> {
        if script.witness_version().unwrap() != WitnessVersion::V0 || script.len() == 22 || script.len() == 34 {
            Some(RawTemplate::SegWit(RawSegWitTemplate::UnknownVersionDoNotUse(Private(script))))
        } else {
            None
        }
    }
}

/// A reference to the bytes of serialized public key.
///
/// The serialized public key can be 33 or 65 bytes long. This type represents the two
/// possibilities as `enum`.
///
/// Note that this behaves like a collection of bytes with many standard methods implemented.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PubkeyBytes<'a> {
    /// The bytes of a compressed public key.
    Compressed(&'a [u8; 33]),
    /// The bytes of an uncompressed public key.
    Uncompressed(&'a [u8; 65]),
}

impl <'a> PubkeyBytes<'a> {
    /// Tries to parse the bytes as public key.
    pub fn to_pubkey(&self) -> Result<PublicKey, crate::key::Error> {
        PublicKey::from_slice(self)
    }

    /// Converts the bytes to a slice.
    ///
    /// As opposed to `Deref` and other traits this doesn't reborrow `self` which makes it possible
    /// to return a slice with the same lifetime as the lifetime of the array stored inside.
    pub const fn to_slice(self) -> &'a [u8] {
        match self {
            PubkeyBytes::Compressed(bytes) => bytes,
            PubkeyBytes::Uncompressed(bytes) => bytes,
        }
    }

    /// Serializes a public key and runs the closure with the serialized bytes passed in as
    /// parameter.
    pub fn with_pubkey<R, F: FnOnce(PubkeyBytes<'_>) -> R>(pubkey: &PublicKey, f: F) -> R {
        if pubkey.compressed {
            f(PubkeyBytes::Compressed(&pubkey.inner.serialize()))
        } else {
            f(PubkeyBytes::Uncompressed(&pubkey.inner.serialize_uncompressed()))
        }
    }
}

impl<'a> Deref for PubkeyBytes<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            PubkeyBytes::Compressed(bytes) => *bytes,
            PubkeyBytes::Uncompressed(bytes) => *bytes,
        }
    }
}

impl<'a> AsRef<[u8]> for PubkeyBytes<'a> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<'a> Borrow<[u8]> for PubkeyBytes<'a> {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl<'a> IntoIterator for PubkeyBytes<'a> {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    fn into_iter(self) -> Self::IntoIter {
        self.to_slice().iter()
    }
}

impl<'a> TryFrom<&'a [u8]> for PubkeyBytes<'a> {
    type Error = PubkeyBytesFromSliceError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if let Ok(compressed) = bytes.try_into() {
            Ok(PubkeyBytes::Compressed(compressed))
        } else if let Ok(uncompressed) = bytes.try_into() {
            Ok(PubkeyBytes::Uncompressed(uncompressed))
        } else {
            Err(PubkeyBytesFromSliceError(bytes.len()))
        }
    }
}

impl<'a> From<PubkeyBytes<'a>> for &'a [u8] {
    fn from(value: PubkeyBytes<'a>) -> Self {
        value.to_slice()
    }
}

/// Error returned when conversion of a byte slice to [`PubkeyBytes`] fails.
#[derive(Debug, Clone)]
pub struct PubkeyBytesFromSliceError(usize);

impl fmt::Display for PubkeyBytesFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid length {} of pubkey bytes - must be 32 or 64", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PubkeyBytesFromSliceError {}

/// A pay-to-witness-something script template.
///
/// Along with the visible variants, this contains a trick which allows getting the version and
/// program of unknown witness versions.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RawSegWitTemplate<'a> {
    /// Pay to witness public key hash.
    P2WPkh(&'a [u8; 20]),

    /// Pay to witness script hash.
    P2WSh(&'a [u8; 32]),

    /// Pay to taproot.
    P2Tr(&'a [u8; 32]),

    /// DO NOT USE! Use [`version`](Self::version) and [`program`](Self::program) methods instead.
    ///
    /// This is future-proofing to be able to store data for unknown versions while still making it
    /// possible to remove the variant and make the enum not non-exhaustive if one day all 16
    /// versions get defined.
    #[doc(hidden)]
    UnknownVersionDoNotUse(Private<&'a Script>),
}

impl<'a> RawSegWitTemplate<'a> {
    /// Returns the witness verstion used in the template.
    pub fn version(&self) -> WitnessVersion {
        match self {
            RawSegWitTemplate::P2WPkh(_) => WitnessVersion::V0,
            RawSegWitTemplate::P2WSh(_) => WitnessVersion::V0,
            RawSegWitTemplate::P2Tr(_) => WitnessVersion::V1,
            RawSegWitTemplate::UnknownVersionDoNotUse(script) => script.0.witness_version().expect("variant always contains a valid witness script")
        }
    }

    /// Returns the witness program used in the template.
    pub fn program(&self) -> &'a [u8] {
        match self {
            RawSegWitTemplate::P2WPkh(program) => *program,
            RawSegWitTemplate::P2WSh(program) => *program,
            RawSegWitTemplate::P2Tr(program) => *program,
            RawSegWitTemplate::UnknownVersionDoNotUse(script) => &script.0.as_bytes()[2..]
        }
    }

    ///  Returns `true` if this is a pay-to-witness-public-key-hash.
    pub const fn is_p2wpkh(&self) -> bool {
        matches!(self, RawSegWitTemplate::P2WPkh(_))
    }

    ///  Returns `true` if this is a pay-to-witness-script-hash.
    pub const fn is_p2wsh(&self) -> bool {
        matches!(self, RawSegWitTemplate::P2WSh(_))
    }

    ///  Returns `true` if this is a pay-to-taproot.
    pub const fn is_p2tr(&self) -> bool {
        matches!(self, RawSegWitTemplate::P2Tr(_))
    }
}

/// Discourages people accessing `UnknownVersionDoNotUse` variant since it forbids access to the
/// contents and its construction.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[doc(hidden)]
pub struct Private<T>(T);
