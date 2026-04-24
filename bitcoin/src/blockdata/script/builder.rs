// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use super::{opcode_to_verify, Error, PushBytes, Script, ScriptBuf};
use crate::key::{FullPublicKey, LegacyPublicKey, PubkeyHash, SerializedLegacyPublicKey, XOnlyPublicKey};
use crate::locktime::absolute;
use crate::opcodes::all::*;
use crate::opcodes::Opcode;
use crate::prelude::Vec;
use crate::script::{ScriptBufExt as _, ScriptBufExtPriv as _, ScriptExtPriv as _, RedeemScriptTag, ScriptHash, ScriptPubKeyTag, ScriptSigTag, TapScriptTag, WitnessScriptTag, WPubkeyHash};
use crate::{relative, Sequence};

/// An Object which can be used to construct a script piece by piece.
///
/// # Panics
///
/// `Builder` is backed by [`ScriptBuf`] and inherits its panic behavior. This means that
/// attempting to construct scripts larger than `isize::MAX` bytes will panic.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder<T>(ScriptBuf<T>, Option<Opcode>);

impl<T> Builder<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { Self(ScriptBuf::new(), None) }

    /// Constructs a new empty script builder with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self { Self(ScriptBuf::with_capacity(capacity), None) }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    ///
    /// # Errors
    ///
    /// Only errors if `data == i32::MIN` (CScriptNum cannot have value -2^31).
    pub fn push_int(mut self, n: i32) -> Result<Self, Error> {
        self.0.push_int(n)?;
        self.1 = None;
        Ok(self)
    }

    /// Adds instructions to push an unchecked integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    ///
    /// This function implements `CScript::push_int64` from Core `script.h`.
    ///
    /// > Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
    /// > The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
    /// > but results may overflow (and are valid as long as they are not used in a subsequent
    /// > numeric operation). CScriptNum enforces those semantics by storing results as
    /// > an int64 and allowing out-of-range values to be returned as a vector of bytes but
    /// > throwing an exception if arithmetic is done or the result is interpreted as an integer.
    ///
    /// Does not check whether `n` is in the range of [-2^31 +1...2^31 -1].
    pub fn push_int_unchecked(mut self, n: i64) -> Self {
        self.0.push_int_unchecked(n);
        self.1 = None;
        self
    }

    /// Adds instructions to push an integer onto the stack without optimization.
    ///
    /// This uses the explicit encoding regardless of the availability of dedicated opcodes.
    pub(in crate::blockdata) fn push_int_non_minimal(mut self, data: i64) -> Self {
        self.0.push_int_non_minimal(data);
        self.1 = None;
        self
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// If the data can be exactly produced by a numeric opcode, that opcode
    /// will be used, since its behavior is equivalent but will not violate minimality
    /// rules. To avoid this, use [`Builder::push_slice_non_minimal`] which will always
    /// use a push opcode.
    ///
    /// However, this method does *not* enforce any numeric minimality rules.
    /// If your pushes should be interpreted as numbers, ensure your input does
    /// not have any leading zeros. In particular, the number 0 should be encoded
    /// as an empty string rather than as a single 0 byte.
    pub fn push_slice<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice(data);
        self.1 = None;
        self
    }

    /// Adds instructions to push some arbitrary data onto the stack without minimality.
    ///
    /// Standardness rules require push minimality according to [CheckMinimalPush] of core.
    ///
    /// [CheckMinimalPush]: <https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.cpp#L366>
    pub fn push_slice_non_minimal<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice_non_minimal(data);
        self.1 = None;
        self
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(mut self, data: Opcode) -> Self {
        self.0.push_opcode(data);
        self.1 = Some(data);
        self
    }

    /// Adds an `OP_VERIFY` to the script or replaces the last opcode with VERIFY form.
    ///
    /// Some opcodes such as `OP_CHECKSIG` have a verify variant that works as if `VERIFY` was
    /// in the script right after. To save space this function appends `VERIFY` only if
    /// the most-recently-added opcode *does not* have an alternate `VERIFY` form. If it does
    /// the last opcode is replaced. E.g., `OP_CHECKSIG` will become `OP_CHECKSIGVERIFY`.
    ///
    /// Note that existing `OP_*VERIFY` opcodes do not lead to the instruction being ignored
    /// because `OP_VERIFY` consumes an item from the stack so ignoring them would change the
    /// semantics.
    pub fn push_verify(mut self) -> Self {
        // "duplicated code" because we need to update `1` field
        match opcode_to_verify(self.1) {
            Some(opcode) => {
                (self.0).as_byte_vec().pop();
                self.push_opcode(opcode)
            }
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Adds instructions to push a public key onto the stack.
    pub fn push_key<K: PubkeyInScript<T>>(self, key: K) -> Self {
        self.push_slice(key.serialize())
    }

    /// Adds instructions to push an XOnly public key onto the stack.
    #[deprecated(since = "TBD", note = "Use push_key instead")]
    pub fn push_x_only_key(self, x_only_key: XOnlyPublicKey) -> Self {
        self.push_slice(x_only_key.serialize().0)
    }

    /// Adds instructions to push an absolute lock time onto the stack.
    pub fn push_lock_time(self, lock_time: absolute::LockTime) -> Self {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a relative lock time onto the stack.
    ///
    /// This is used when creating scripts that use CHECKSEQUENCEVERIFY (CSV) to enforce
    /// relative time locks.
    pub fn push_relative_lock_time(self, lock_time: relative::LockTime) -> Self {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a sequence number onto the stack.
    ///
    /// # Deprecated
    /// This method is deprecated in favor of `push_relative_lock_time`.
    ///
    /// In Bitcoin script semantics, when using CHECKSEQUENCEVERIFY, you typically
    /// want to push a relative locktime value to be compared against the input's
    /// sequence number, not the sequence number itself.
    #[deprecated(
        since = "TBD",
        note = "Use push_relative_lock_time instead for working with timelocks in scripts"
    )]
    pub fn push_sequence(self, sequence: Sequence) -> Self {
        self.push_int_unchecked(sequence.to_consensus_u32().into())
    }

    /// Pushes instructions verifying that the top-most stack element hashes to `hash`.
    ///
    /// This is equivalent to `{HASH_OP} <hash> OP_EQUAL` with a few advantages:
    ///
    /// * Statically enforced correct instruction for the given type
    /// * Easy changing of the type if needed
    /// * More convenient to write
    ///
    /// Beware that this does NOT push `OP_DUP` - you need to push it yourself, if needed.
    ///
    /// This method works optimally with [`push_verify`](Self::push_verify).
    pub fn push_check_hash<H: HashInScript<T>>(self, hash: H) -> Self {
        self.push_opcode(H::OPCODE)
            .push_slice(hash)
            .push_opcode(OP_EQUAL)
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf<T> { self.0 }

    /// Converts the `Builder` into script bytes
    pub fn into_bytes(self) -> Vec<u8> { self.0.into() }

    /// Returns the internal script
    pub fn as_script(&self) -> &Script<T> { &self.0 }

    /// Returns script bytes
    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
}

impl<T> Default for Builder<T> {
    fn default() -> Self { Self::new() }
}

/// Constructs a new builder from an existing vector.
impl<T> From<Vec<u8>> for Builder<T> {
    fn from(v: Vec<u8>) -> Self {
        let script = ScriptBuf::from(v);
        let last_op = script.last_opcode();
        Self(script, last_op)
    }
}

impl<T> fmt::Display for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl<T> fmt::Debug for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

/// Represents hashes that are natively supported by the bitcoin script.
///
/// This is intended for use with [`Builder::push_check_hash`] but you can bound on it in generic
/// functions if you need to make scripts generic over hash type.
pub trait HashInScript<Tag>: AsRef<PushBytes> {
    /// The opcode that hashes the top-most element on the stack producing a `Self`-like hash type.
    const OPCODE: Opcode;
}

impl<U, T: HashInScript<U>> HashInScript<U> for &'_ T {
    const OPCODE: Opcode = T::OPCODE;
}

macro_rules! impl_hash_in_script_for_tags {
    ($hash:ident, $opcode:ident $(, $tag:ident)*) => {
        $(
            impl HashInScript<primitives::script::$tag> for hashes::$hash::Hash {
                const OPCODE: Opcode = $opcode;
            }
        )*
    }
}

macro_rules! impl_each_hash_in_script {
    ($($hash:ident => $opcode:ident,)*) => {
        $(
            impl_hash_in_script_for_tags!($hash, $opcode, RedeemScriptTag, ScriptPubKeyTag, SignetBlockScriptTag, TapScriptTag, WitnessScriptTag);
        )*
    }
}

impl_each_hash_in_script! {
    hash160 => OP_HASH160,
    ripemd160 => OP_RIPEMD160,
    sha1 => OP_SHA1,
    sha256 => OP_SHA256,
    sha256d => OP_HASH256,
}

impl HashInScript<ScriptPubKeyTag> for PubkeyHash {
    const OPCODE: Opcode = OP_HASH160;
}

impl HashInScript<ScriptPubKeyTag> for ScriptHash {
    const OPCODE: Opcode = OP_HASH160;
}

/// While `W` suggests "witness", the type is technically correct in `script_pubkey` since it's
/// just hashed compressed key.
impl HashInScript<ScriptPubKeyTag> for WPubkeyHash {
    const OPCODE: Opcode = OP_HASH160;
}

/// Represents public keys or their standard hashes that are natively supported by bitcoin script.
pub trait PubkeyInScript<Tag> {
    /// The container type holding the bytes of a serialized key.
    type Serialized: AsRef<PushBytes>;

    /// Serializes the key.
    #[must_use]
    fn serialize(&self) -> Self::Serialized;
}

impl<U, T: PubkeyInScript<U>> PubkeyInScript<U> for &'_ T {
    type Serialized = T::Serialized;

    fn serialize(&self) -> Self::Serialized {
        (*self).serialize()
    }
}

impl PubkeyInScript<ScriptPubKeyTag> for LegacyPublicKey {
    type Serialized = SerializedLegacyPublicKey;

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

// Keys may appear in sript_sig in case of P2PKH.
impl PubkeyInScript<ScriptSigTag> for LegacyPublicKey {
    type Serialized = SerializedLegacyPublicKey;

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

impl PubkeyInScript<RedeemScriptTag> for LegacyPublicKey {
    type Serialized = SerializedLegacyPublicKey;

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

impl PubkeyInScript<ScriptPubKeyTag> for FullPublicKey {
    type Serialized = [u8; 33];

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

impl PubkeyInScript<RedeemScriptTag> for FullPublicKey {
    type Serialized = [u8; 33];

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

impl PubkeyInScript<WitnessScriptTag> for FullPublicKey {
    type Serialized = [u8; 33];

    fn serialize(&self) -> Self::Serialized {
        self.to_bytes()
    }
}

impl PubkeyInScript<TapScriptTag> for XOnlyPublicKey {
    type Serialized = [u8; 32];

    fn serialize(&self) -> Self::Serialized {
        self.serialize().0
    }
}

impl PubkeyInScript<ScriptPubKeyTag> for PubkeyHash {
    type Serialized = Self;

    fn serialize(&self) -> Self::Serialized {
        *self
    }
}

impl PubkeyInScript<RedeemScriptTag> for PubkeyHash {
    type Serialized = Self;

    fn serialize(&self) -> Self::Serialized {
        *self
    }
}

/// While `W` suggests "witness", the type is technically correct in `script_pubkey` since it's
/// just hashed compressed key.
impl PubkeyInScript<ScriptPubKeyTag> for WPubkeyHash {
    type Serialized = Self;

    fn serialize(&self) -> Self::Serialized {
        *self
    }
}

/// While `W` suggests "witness", the type is technically correct in `script_pubkey` since it's
/// just hashed compressed key.
impl PubkeyInScript<RedeemScriptTag> for WPubkeyHash {
    type Serialized = Self;

    fn serialize(&self) -> Self::Serialized {
        *self
    }
}

impl PubkeyInScript<WitnessScriptTag> for WPubkeyHash {
    type Serialized = Self;

    fn serialize(&self) -> Self::Serialized {
        *self
    }
}
