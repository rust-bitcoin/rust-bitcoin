// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.

mod borrowed;
mod owned;

use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;

use hashes::{hash160, sha256};
#[cfg(feature = "hex")]
use hex::DisplayHex;
use internals::script::{self, PushDataLenLen};

#[allow(clippy::wildcard_imports)]
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::prelude::rc::Rc;
#[cfg(target_has_atomic = "ptr")]
use crate::prelude::sync::Arc;
use crate::prelude::{Borrow, BorrowMut, Box, Cow, ToOwned, Vec};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::{Script, ScriptSig, ScriptPubkey, RedeemScript, WitnessScript, TapScript},
    owned::{ScriptBuf, ScriptSigBuf, ScriptPubkeyBuf, RedeemScriptBuf, WitnessScriptBuf, TapScriptBuf},
};

/// The maximum allowed redeem script size for a P2SH output.
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;
/// The maximum allowed redeem script size of the witness script.
pub const MAX_WITNESS_SCRIPT_SIZE: usize = 10_000;

hashes::hash_newtype! {
    /// A 160-bit hash of Bitcoin Script bytecode.
    ///
    /// Note: there is another "script hash" object in bitcoin ecosystem (Electrum protocol) that
    /// uses 256-bit hash and hashes a semantically different script. Thus, this type cannot
    /// represent it.
    pub struct ScriptHash(hash160::Hash);

    /// SegWit (256-bit) version of a Bitcoin Script bytecode hash.
    ///
    /// Note: there is another "script hash" object in bitcoin ecosystem (Electrum protocol) that
    /// looks similar to this one also being SHA256, however, they hash semantically different
    /// scripts and have reversed representations, so this type cannot be used for both.
    pub struct WScriptHash(sha256::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(ScriptHash, WScriptHash);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(ScriptHash, WScriptHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(ScriptHash, WScriptHash);

impl ScriptHash {
    /// Constructs a new `ScriptHash` after first checking the script size.
    ///
    /// # 520-byte limitation on serialized script size
    ///
    /// > As a consequence of the requirement for backwards compatibility the serialized script is
    /// > itself subject to the same rules as any other PUSHDATA operation, including the rule that
    /// > no data greater than 520 bytes may be pushed to the stack. Thus it is not possible to
    /// > spend a P2SH output if the redemption script it refers to is >520 bytes in length.
    ///
    /// ref: [BIP-16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size)
    #[inline]
    pub fn from_script(script: &RedeemScript) -> Result<Self, RedeemScriptSizeError> {
        if script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(RedeemScriptSizeError { size: script.len() });
        }

        // We've just checked the length
        Ok(ScriptHash::from_script_unchecked(script))
    }

    /// Constructs a new `ScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 520 bytes in size and use it to create a P2SH output
    /// then the output will be unspendable (see [BIP-16]).
    ///
    /// [BIP-16]: <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size>
    #[inline]
    pub fn from_script_unchecked(script: &RedeemScript) -> Self {
        ScriptHash(hash160::Hash::hash(script.as_bytes()))
    }
}

impl WScriptHash {
    /// Constructs a new `WScriptHash` after first checking the script size.
    ///
    /// # 10,000-byte limit on the witness script
    ///
    /// > The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the
    /// > witnessScript must match the 32-byte witness program.
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script(script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        if script.len() > MAX_WITNESS_SCRIPT_SIZE {
            return Err(WitnessScriptSizeError { size: script.len() });
        }

        // We've just checked the length
        Ok(WScriptHash::from_script_unchecked(script))
    }

    /// Constructs a new `WScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 10,000 bytes in size and use it to create a Segwit
    /// output then the output will be unspendable (see [BIP-141]).
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script_unchecked(script: &WitnessScript) -> Self {
        WScriptHash(sha256::Hash::hash(script.as_bytes()))
    }
}

impl TryFrom<RedeemScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(script: RedeemScriptBuf) -> Result<Self, Self::Error> { Self::from_script(&script) }
}

impl TryFrom<&RedeemScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(script: &RedeemScriptBuf) -> Result<Self, Self::Error> { Self::from_script(script) }
}

impl TryFrom<&RedeemScript> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(script: &RedeemScript) -> Result<Self, Self::Error> { Self::from_script(script) }
}

impl TryFrom<WitnessScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(script: WitnessScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&script)
    }
}

impl TryFrom<&WitnessScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(script: &WitnessScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(script)
    }
}

impl TryFrom<&WitnessScript> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(script: &WitnessScript) -> Result<Self, Self::Error> { Self::from_script(script) }
}

/// Error while hashing a redeem script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemScriptSizeError {
    /// Invalid redeem script size (cannot exceed 520 bytes).
    size: usize,
}

impl RedeemScriptSizeError {
    /// Returns the invalid redeem script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

impl From<Infallible> for RedeemScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for RedeemScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "redeem script size exceeds {} bytes: {}", MAX_REDEEM_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RedeemScriptSizeError {}

/// Error while hashing a witness script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessScriptSizeError {
    /// Invalid witness script size (cannot exceed 10,000 bytes).
    size: usize,
}

impl WitnessScriptSizeError {
    /// Returns the invalid witness script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

impl From<Infallible> for WitnessScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for WitnessScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "witness script size exceeds {} bytes: {}", MAX_WITNESS_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessScriptSizeError {}

/// Marker for scripts that are used as a scriptSig.
///
/// This type is not intended to be use directly, instead use [`ScriptSig`] or [`ScriptSigBuf`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptSigTag {}

/// Marker for scripts that are used as a scriptPubkey.
///
/// This type is not intended to be use directly, instead use [`ScriptPubkey`] or [`ScriptPubkeyBuf`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptPubkeyTag {}

/// Marker for scripts that are used as a redeemScript i.e., P2SH.
///
/// This type is not intended to be use directly, instead use [`RedeemScript`] or [`RedeemScriptBuf`].
///
/// A `RedeemScript` is a `ScriptPubkey` that is used during the second round of verification
/// of a P2SH output.
///
/// Can be explicitly converted to/from a [`ScriptPubkey`]. See [`RedeemScript::as_script_pubkey`]
/// and [`RedeemScriptBuf::into_script_pubkey`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedeemScriptTag {}

/// Marker for scripts that are used as a witness stack script i.e., P2WSH and P2SH-P2WSH.
///
/// This type is not intended to be use directly, instead use [`WitnessScript`] or [`WitnessScriptBuf`].
///
/// A `WitnessScript` is a `ScriptPubkey` that is used during the second round of verification
/// of a P2WSH output. Witness scripts have slightly different semantics to pre-segwit scripts.
/// See [BIP-141 New Script Semantics].
///
/// Can be explicitly converted to/from a [`ScriptPubkey`]. See [`WitnessScript::as_script_pubkey`]
/// and [`WitnessScriptBuf::into_script_pubkey`].
///
/// [BIP-141 New Script Semantics]: <https://en.bitcoin.it/wiki/BIP_0141#New_script_semantics>
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WitnessScriptTag {}

/// Marker for scripts that are used as a Tapscript i.e., used in a Taproot script path spend.
///
/// This type is not intended to be use directly, instead use [`TapScript`] or [`TapScriptBuf`].
///
/// A `TapScript` is a `ScriptPubkey` that is used when verifying Taproot script path spends as
/// defined by [BIP-341], "Call the second-to-last stack element s, the script." (see [BIP-341
/// Script validation rules]).
///
/// Can be explicitly converted to/from a [`ScriptPubkey`]. See [`TapScript::as_script_pubkey`] and
/// [`TapScriptBuf::into_script_pubkey`]
///
/// [BIP-141]: <https://en.bitcoin.it/wiki/BIP_0341>
/// [BIP-141 Script validation rules]: <https://en.bitcoin.it/wiki/BIP_0341#Script_validation_rules>
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TapScriptTag {}

/// Marker for scripts for which the context is unknown.
///
/// This type is not intended to be use directly, instead use [`Script`] or [`ScriptBuf`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextUnknownTag {}

/// Context that the associated script is used in e.g., scriptPubkey.
///
/// This trait is used to define script context tags. It does not define any behaviour and is not
/// implementable by downstream users.  
pub trait Context: sealed::Context + Sync + Send + Sized + Unpin + Copy {}

impl Context for ScriptPubkeyTag {}
impl Context for ScriptSigTag {}
impl Context for RedeemScriptTag {}
impl Context for WitnessScriptTag {}
impl Context for TapScriptTag {}
impl Context for ContextUnknownTag {}

mod sealed {
    pub trait Context {}
    impl Context for super::ScriptPubkeyTag {}
    impl Context for super::ScriptSigTag {}
    impl Context for super::RedeemScriptTag {}
    impl Context for super::WitnessScriptTag {}
    impl Context for super::TapScriptTag {}
    impl Context for super::ContextUnknownTag {}
}

// We keep all the `Script` and `ScriptBuf` impls together since its easier to see side-by-side.

impl<C: Context> From<owned::tmp::ScriptBuf<C>> for Box<borrowed::tmp::Script<C>> {
    #[inline]
    fn from(v: owned::tmp::ScriptBuf<C>) -> Self { v.into_boxed_script() }
}

impl<C: Context> From<owned::tmp::ScriptBuf<C>> for Cow<'_, borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: owned::tmp::ScriptBuf<C>) -> Self { Cow::Owned(value) }
}

impl<'a, C: Context> From<Cow<'a, borrowed::tmp::Script<C>>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn from(value: Cow<'a, borrowed::tmp::Script<C>>) -> Self {
        match value {
            Cow::Owned(owned) => owned,
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a, C: Context> From<Cow<'a, borrowed::tmp::Script<C>>> for Box<borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: Cow<'a, borrowed::tmp::Script<C>>) -> Self {
        match value {
            Cow::Owned(owned) => owned.into(),
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a, C: Context> From<&'a borrowed::tmp::Script<C>> for Box<borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: &'a borrowed::tmp::Script<C>) -> Self { value.to_owned().into() }
}

impl<'a, C: Context> From<&'a borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn from(value: &'a borrowed::tmp::Script<C>) -> Self { value.to_owned() }
}

impl<'a, C: Context> From<&'a borrowed::tmp::Script<C>> for Cow<'a, borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: &'a borrowed::tmp::Script<C>) -> Self { Cow::Borrowed(value) }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(target_has_atomic = "ptr")]
impl<'a, C: Context> From<&'a borrowed::tmp::Script<C>> for Arc<borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: &'a borrowed::tmp::Script<C>) -> Self {
        borrowed::tmp::Script::from_arc_bytes(Arc::from(value.as_bytes()))
    }
}

impl<'a, C: Context> From<&'a borrowed::tmp::Script<C>> for Rc<borrowed::tmp::Script<C>> {
    #[inline]
    fn from(value: &'a borrowed::tmp::Script<C>) -> Self {
        borrowed::tmp::Script::from_rc_bytes(Rc::from(value.as_bytes()))
    }
}

impl<C: Context> From<Vec<u8>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn from(v: Vec<u8>) -> Self { owned::tmp::ScriptBuf::from_bytes(v) }
}

impl<C: Context> From<owned::tmp::ScriptBuf<C>> for Vec<u8> {
    #[inline]
    fn from(v: owned::tmp::ScriptBuf<C>) -> Self { v.into_bytes() }
}

impl<C: Context> AsRef<borrowed::tmp::Script<C>> for borrowed::tmp::Script<C> {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}

impl<C: Context> AsRef<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn as_ref(&self) -> &borrowed::tmp::Script<C> { self }
}

impl<C: Context> AsRef<[u8]> for borrowed::tmp::Script<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl<C: Context> AsRef<[u8]> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl<C: Context> AsMut<borrowed::tmp::Script<C>> for borrowed::tmp::Script<C> {
    #[inline]
    fn as_mut(&mut self) -> &mut Self { self }
}

impl<C: Context> AsMut<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn as_mut(&mut self) -> &mut borrowed::tmp::Script<C> { self }
}

impl<C: Context> AsMut<[u8]> for borrowed::tmp::Script<C> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl<C: Context> AsMut<[u8]> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl<C: Context> fmt::Debug for borrowed::tmp::Script<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl<C: Context> fmt::Debug for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(self.as_script(), f) }
}

impl<C: Context> fmt::Display for borrowed::tmp::Script<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // This has to be a macro because it needs to break the loop
        macro_rules! read_push_data_len {
            ($iter:expr, $size:path, $formatter:expr) => {
                match script::read_push_data_len($iter, $size) {
                    Ok(n) => n,
                    Err(_) => {
                        $formatter.write_str("<unexpected end>")?;
                        break;
                    }
                }
            };
        }

        let mut iter = self.as_bytes().iter();
        // Was at least one opcode emitted?
        let mut at_least_one = false;
        // `iter` needs to be borrowed in `read_push_data_len`, so we have to use `while let` instead
        // of `for`.
        while let Some(byte) = iter.next() {
            let opcode = Opcode::from(*byte);

            let data_len = if let opcodes::Class::PushBytes(n) =
                opcode.classify(opcodes::ClassifyContext::Legacy)
            {
                n as usize
            } else {
                match opcode {
                    OP_PUSHDATA1 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::One, f)
                    }
                    OP_PUSHDATA2 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::Two, f)
                    }
                    OP_PUSHDATA4 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::Four, f)
                    }
                    _ => 0,
                }
            };

            if at_least_one {
                f.write_str(" ")?;
            } else {
                at_least_one = true;
            }
            // Write the opcode
            if opcode == OP_PUSHBYTES_0 {
                f.write_str("OP_0")?;
            } else {
                write!(f, "{:?}", opcode)?;
            }
            // Write any pushdata
            if data_len > 0 {
                f.write_str(" ")?;
                if data_len <= iter.len() {
                    for ch in iter.by_ref().take(data_len) {
                        write!(f, "{:02x}", ch)?;
                    }
                } else {
                    f.write_str("<push past end>")?;
                    break;
                }
            }
        }
        Ok(())
    }
}

impl<C: Context> fmt::Display for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self.as_script(), f) }
}

#[cfg(feature = "hex")]
impl<C: Context> fmt::LowerHex for borrowed::tmp::Script<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl<C: Context> fmt::LowerHex for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self.as_script(), f) }
}

#[cfg(feature = "hex")]
impl<C: Context> fmt::UpperHex for borrowed::tmp::Script<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl<C: Context> fmt::UpperHex for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(self.as_script(), f) }
}

impl<C: Context> Borrow<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn borrow(&self) -> &borrowed::tmp::Script<C> { self }
}

impl<C: Context> BorrowMut<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut borrowed::tmp::Script<C> { self }
}

impl<C: Context> PartialEq<owned::tmp::ScriptBuf<C>> for borrowed::tmp::Script<C> {
    #[inline]
    fn eq(&self, other: &owned::tmp::ScriptBuf<C>) -> bool { self.as_bytes().eq(other.as_bytes()) }
}

impl<C: Context> PartialEq<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn eq(&self, other: &borrowed::tmp::Script<C>) -> bool { self.as_bytes().eq(other.as_bytes()) }
}

impl<C: Context> PartialOrd<borrowed::tmp::Script<C>> for owned::tmp::ScriptBuf<C> {
    #[inline]
    fn partial_cmp(&self, other: &borrowed::tmp::Script<C>) -> Option<Ordering> {
        self.as_bytes().partial_cmp(other.as_bytes())
    }
}

impl<C: Context> PartialOrd<owned::tmp::ScriptBuf<C>> for borrowed::tmp::Script<C> {
    #[inline]
    fn partial_cmp(&self, other: &owned::tmp::ScriptBuf<C>) -> Option<Ordering> {
        self.as_bytes().partial_cmp(other.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<C: Context> serde::Serialize for borrowed::tmp::Script<C> {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{:x}", self))
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

/// Can only deserialize borrowed bytes.
#[cfg(feature = "serde")]
impl<'de, C: Context> serde::Deserialize<'de> for &'de borrowed::tmp::Script<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::marker::PhantomData;

        struct Visitor<C>(PhantomData<C>);

        impl<'de, C: Context + 'de> serde::de::Visitor<'de> for Visitor<C> {
            type Value = &'de borrowed::tmp::Script<C>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("borrowed bytes")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(borrowed::tmp::Script::from_bytes(v))
            }
        }

        if deserializer.is_human_readable() {
            use crate::serde::de::Error;
            return Err(D::Error::custom(
                "deserialization of `&Script` from human-readable formats is not possible",
            ));
        }

        deserializer.deserialize_bytes(Visitor(std::marker::PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<C: Context> serde::Serialize for owned::tmp::ScriptBuf<C> {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C: Context> serde::Deserialize<'de> for owned::tmp::ScriptBuf<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        use hex::FromHex;
        if deserializer.is_human_readable() {
            struct Visitor<C>(std::marker::PhantomData<C>);
            impl<C: Context> serde::de::Visitor<'_> for Visitor<C> {
                type Value = owned::tmp::ScriptBuf<C>;
                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }
                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let v = Vec::from_hex(v).map_err(E::custom)?;
                    Ok(owned::tmp::ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_str(Visitor(std::marker::PhantomData))
        } else {
            struct BytesVisitor<C>(std::marker::PhantomData<C>);
            impl<C: Context> serde::de::Visitor<'_> for BytesVisitor<C> {
                type Value = owned::tmp::ScriptBuf<C>;
                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script Vec<u8>")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(owned::tmp::ScriptBuf::from(v.to_vec()))
                }
                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(owned::tmp::ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_byte_buf(BytesVisitor(std::marker::PhantomData))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scriptbuf_from_vec_u8() {
        let vec = vec![0x51, 0x52, 0x53];
        let script_buf: ScriptPubkeyBuf = vec.clone().into();
        let result: Vec<u8> = script_buf.into();
        assert_eq!(result, vec);
    }

    #[test]
    fn scriptbuf_as_ref() {
        let script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let script_ref: &[u8] = script_buf.as_ref();
        assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

        let script_ref: &ScriptPubkey = script_buf.as_ref();
        assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn scriptbuf_as_mut() {
        let mut script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);

        let script_mut: &mut [u8] = script_buf.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);

        let script_mut: &mut ScriptPubkey = script_buf.as_mut();
        script_mut.as_mut_bytes()[1] = 0x51;
        assert_eq!(script_buf.as_bytes(), &[0x50, 0x51, 0x53]);
    }

    #[test]
    fn scriptbuf_borrow_mut() {
        let mut script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let script_mut: &mut ScriptPubkey = script_buf.borrow_mut();
        script_mut.as_mut_bytes()[0] = 0x50;

        assert_eq!(script_buf.as_bytes(), &[0x50, 0x52, 0x53]);
    }

    #[test]
    #[allow(clippy::useless_asref)]
    fn script_as_ref() {
        let script = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let script_ref: &[u8] = script.as_ref();
        assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

        let script_ref: &ScriptPubkey = script.as_ref();
        assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    #[allow(clippy::useless_asref)]
    fn script_as_mut() {
        let bytes = &mut [0x51, 0x52, 0x53];
        let script = ScriptPubkey::from_bytes_mut(bytes);

        let script_mut: &mut [u8] = script.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);

        let script_mut: &mut ScriptPubkey = script.as_mut();
        script_mut.as_mut_bytes()[1] = 0x51;
        assert_eq!(script.as_bytes(), &[0x50, 0x51, 0x53]);
    }

    #[test]
    fn partial_ord() {
        let script_small = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let script_big = ScriptPubkey::from_bytes(&[0x54, 0x55, 0x56]);
        let script_buf_small = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let script_buf_big = ScriptPubkeyBuf::from(vec![0x54, 0x55, 0x56]);

        assert!(script_small == &script_buf_small);
        assert!(script_buf_small == *script_small);
        assert!(script_small != &script_buf_big);
        assert!(script_buf_small != *script_big);

        assert!(script_small < &script_buf_big);
        assert!(script_buf_small < *script_big);
        assert!(script_big > &script_buf_small);
        assert!(script_buf_big > *script_small);
    }

    #[test]
    fn script_hash_from_script() {
        let script = RedeemScript::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::from_script(script).is_ok());

        let script = RedeemScript::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::from_script(script).is_err());
    }

    #[test]
    fn script_hash_from_script_unchecked() {
        let script = RedeemScript::from_bytes(&[0x51; 521]);
        let hash = ScriptHash::from_script_unchecked(script);
        assert_eq!(hash, ScriptHash(hash160::Hash::hash(script.as_bytes())));
    }

    #[test]
    fn wscript_hash_from_script() {
        let script = WitnessScript::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::from_script(script).is_ok());

        let script = WitnessScript::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::from_script(script).is_err());
    }

    #[test]
    fn wscript_hash_from_script_unchecked() {
        let script = WitnessScript::from_bytes(&[0x51; 10_001]);
        let hash = WScriptHash::from_script_unchecked(script);
        assert_eq!(hash, WScriptHash(sha256::Hash::hash(script.as_bytes())));
    }

    #[test]
    fn try_from_scriptbuf_for_scripthash() {
        let script = RedeemScriptBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = RedeemScriptBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_ref_for_scripthash() {
        let script = RedeemScriptBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(&script).is_ok());

        let script = RedeemScriptBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(&script).is_err());
    }

    #[test]
    fn try_from_script_for_scripthash() {
        let script = RedeemScript::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = RedeemScript::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_for_wscript_hash() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_ref_for_wscript_hash() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(&script).is_ok());

        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(&script).is_err());
    }

    #[test]
    fn try_from_script_for_wscript_hash() {
        let script = WitnessScript::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = WitnessScript::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn script_display() {
        let script = ScriptPubkey::from_bytes(&[0x00, 0xa1, 0xb2]);
        assert_eq!(format!("{}", script), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script), "00a1b2");
            assert_eq!(format!("{:X}", script), "00A1B2");
        }
        assert!(!format!("{:?}", script).is_empty());
    }

    #[test]
    fn script_display_pushdata() {
        // OP_PUSHDATA1
        let script = Script::from_bytes(&[0x4c, 0x02, 0xab, 0xcd]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA1 abcd");

        // OP_PUSHDATA2
        let script = Script::from_bytes(&[0x4d, 0x02, 0x00, 0x12, 0x34]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA2 1234");

        // OP_PUSHDATA4
        let script = Script::from_bytes(&[0x4e, 0x02, 0x00, 0x00, 0x00, 0x56, 0x78]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA4 5678");
    }

    #[test]
    fn scriptbuf_display() {
        let script_buf = ScriptPubkeyBuf::from(vec![0x00, 0xa1, 0xb2]);
        assert_eq!(format!("{}", script_buf), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script_buf), "00a1b2");
            assert_eq!(format!("{:X}", script_buf), "00A1B2");
        }
        assert!(!format!("{:?}", script_buf).is_empty());
    }

    #[test]
    fn cow_script_to_scriptbuf() {
        let script = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let cow_borrowed: Cow<ScriptPubkey> = Cow::Borrowed(script);
        let script_buf: ScriptPubkeyBuf = cow_borrowed.into();
        assert_eq!(script_buf.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn cow_scriptbuf_to_script() {
        let script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<ScriptPubkey> = Cow::Owned(script_buf.clone());
        let script: &ScriptPubkey = cow_owned.borrow();
        assert_eq!(script.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn cow_scriptbuf_to_box_script() {
        let script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<ScriptPubkey> = Cow::Owned(script_buf.clone());
        let boxed_script: Box<ScriptPubkey> = cow_owned.into();
        let script_buf2 = boxed_script.into_script_buf();
        assert_eq!(script_buf2, script_buf);
    }

    #[test]
    fn cow_owned_to_scriptbuf() {
        let script_buf = ScriptPubkeyBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<ScriptPubkey> = Cow::Owned(script_buf.clone());
        let script_buf_2: ScriptPubkeyBuf = cow_owned.into();
        assert_eq!(script_buf_2, script_buf);
    }

    #[test]
    fn cow_script_to_box_script() {
        let script = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let cow_borrowed: Cow<ScriptPubkey> = Cow::Borrowed(script);
        let boxed_script: Box<ScriptPubkey> = cow_borrowed.into();
        assert_eq!(boxed_script.as_bytes(), &[0x51, 0x52, 0x53]);

        let cow_owned: Cow<ScriptPubkey> = Cow::from(script.to_owned());
        assert_eq!(cow_owned.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);

        let cow_from_script: Cow<ScriptPubkey> = Cow::from(script);
        assert_eq!(cow_from_script.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn redeem_script_size_error() {
        let script = RedeemScriptBuf::from(vec![0x51; 521]);
        let result = ScriptHash::try_from(script);

        let err = result.unwrap_err();
        assert_eq!(err.invalid_size(), 521);

        let err_msg = format!("{}", err);
        assert!(err_msg.contains("521"));
    }

    #[test]
    fn witness_script_size_error() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        let result = WScriptHash::try_from(script);

        let err = result.unwrap_err();
        assert_eq!(err.invalid_size(), 10_001);

        let err_msg = format!("{}", err);
        assert!(err_msg.contains("10001"));
    }

    #[test]
    #[cfg(target_has_atomic = "ptr")]
    fn script_to_arc() {
        let script = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let arc_script: Arc<ScriptPubkey> = Arc::from(script);

        assert_eq!(arc_script.as_bytes(), script.as_bytes());
        assert_eq!(Arc::strong_count(&arc_script), 1);
    }

    #[test]
    fn script_to_rc() {
        let script = ScriptPubkey::from_bytes(&[0x51, 0x52, 0x53]);
        let rc_script: Rc<ScriptPubkey> = Rc::from(script);

        assert_eq!(rc_script.as_bytes(), script.as_bytes());
        assert_eq!(Rc::strong_count(&rc_script), 1);
    }

    #[test]
    fn pushdata_end_conditions() {
        let push_past_end_script = ScriptPubkey::from_bytes(&[0x4c, 0x02]);
        let formatted_script = format!("{}", push_past_end_script);
        assert!(formatted_script.contains("<push past end>"));

        let unexpected_end_script = ScriptPubkey::from_bytes(&[0x4c]);
        let formatted_script = format!("{}", unexpected_end_script);
        assert!(formatted_script.contains("<unexpected end>"));
    }

    #[test]
    fn legacy_opcode() {
        let script = ScriptPubkey::from_bytes(&[0x03, 0xaa, 0xbb, 0xcc]);
        assert_eq!(format!("{}", script), "OP_PUSHBYTES_3 aabbcc");
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn script_to_hex() {
        let script = ScriptPubkey::from_bytes(&[0xa1, 0xb2, 0xc3]);
        let hex = script.to_hex();
        assert_eq!(hex, "a1b2c3");
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn scriptbuf_to_hex() {
        let script = ScriptPubkeyBuf::from_bytes(vec![0xa1, 0xb2, 0xc3]);
        let hex = script.to_hex();
        assert_eq!(hex, "a1b2c3");
    }
}
