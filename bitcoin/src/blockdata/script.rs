// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.
//!
//! *[See also the `Script` type](Script).*
//!
//! This module provides the structures and functions needed to support scripts.
//!
//! <details>
//! <summary>What is Bitcoin script</summary>
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid iff
//! the script leaves `TRUE` on the stack after being evaluated. Bitcoin's
//! script is a stack-based assembly language similar in spirit to [Forth].
//!
//! Script is represented as a sequence of bytes on the wire, each byte representing an operation,
//! or data to be pushed on the stack.
//!
//! See [Bitcoin Wiki: Script][wiki-script] for more information.
//!
//! [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
//!
//! [wiki-script]: https://en.bitcoin.it/wiki/Script
//! </details>
//!
//! In this library we chose to keep the byte representation in memory and decode opcodes only when
//! processing the script. This is similar to Rust choosing to represent strings as UTF-8-encoded
//! bytes rather than slice of `char`s. In both cases the individual items can have different sizes
//! and forcing them to be larger would waste memory and, in case of Bitcoin script, even some
//! performance (forcing allocations).
//!
//! ## `Script` vs `ScriptBuf` vs `Builder`
//!
//! These are the most important types in this module and they are quite similar, so it may seem
//! confusing what the differences are. `Script` is an unsized type much like `str` or `Path` are
//! and `ScriptBuf` is an owned counterpart to `Script` just like `String` is an owned counterpart
//! to `str`.
//!
//! However it is common to construct an owned script and then pass it around. For this case a
//! builder API is more convenient. To support this we provide `Builder` type which is very similar
//! to `ScriptBuf` but its methods take `self` instead of `&mut self` and return `Self`. It also
//! contains a cache that may make some modifications faster. This cache is usually not needed
//! outside of creating the script.
//!
//! At the time of writing there's only one operation using the cache - `push_verify`, so the cache
//! is minimal but we may extend it in the future if needed.

use crate::prelude::*;

use alloc::rc::Rc;
use alloc::sync::Arc;
use bitcoin_internals::debug_from_display;
use crate::io;
use core::cmp::Ordering;
use core::convert::TryFrom;
use core::borrow::{Borrow, BorrowMut};
use core::{fmt, default::Default};
use core::ops::{Deref, DerefMut, Index, Range, RangeFull, RangeFrom, RangeTo, RangeInclusive, RangeToInclusive};
#[cfg(rust_v_1_53)]
use core::ops::Bound;

#[cfg(feature = "serde")] use serde;

use crate::hash_types::{PubkeyHash, WPubkeyHash, ScriptHash, WScriptHash};
use crate::blockdata::opcodes::{self, all::*};
use crate::consensus::{encode, Decodable, Encodable};
use crate::hashes::{Hash, hex};
use crate::policy::DUST_RELAY_TX_FEE;
#[cfg(feature="bitcoinconsensus")] use bitcoinconsensus;
#[cfg(feature="bitcoinconsensus")] use core::convert::From;
use crate::OutPoint;

use crate::key::PublicKey;
use crate::address::{WitnessVersion, WitnessProgram};
use crate::taproot::{LeafVersion, TapNodeHash, TapLeafHash};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use crate::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};

#[cfg(not(rust_v_1_51))] use bitcoin_internals::num::IntExt;

/// Bitcoin script slice.
///
/// *[See also the `bitcoin::blockdata::script` module](crate::blockdata::script).*
///
/// `Script` is a script slice, the most primitive script type. It's usually seen in its borrowed
/// form `&Script`. It is always encoded as a series of bytes representing the opcodes and data
/// pushes.
///
/// ## Validity
///
/// `Script` does not have any validity invariants - it's essentially just a marked slice of
/// bytes. This is similar to [`Path`](std::path::Path) vs [`OsStr`](std::ffi::OsStr) where they
/// are trivially cast-able to each-other and `Path` doesn't guarantee being a usable FS path but
/// having a newtype still has value because of added methods, readability and basic type checking.
///
/// Although at least data pushes could be checked not to overflow the script, bad scripts are
/// allowed to be in a transaction (outputs just become unspendable) and there even are such
/// transactions in the chain. Thus we must allow such scripts to be placed in the transaction.
///
/// ## Slicing safety
///
/// Slicing is similar to how `str` works: some ranges may be incorrect and indexing by
/// `usize` is not supported. However, as opposed to `std`, we have no way of checking
/// correctness without causing linear complexity so there are **no panics on invalid
/// ranges!** If you supply an invalid range, you'll get a garbled script.
///
/// The range is considered valid if it's at a boundary of instruction. Care must be taken
/// especially with push operations because you could get a reference to arbitrary
/// attacker-supplied bytes that look like a valid script.
///
/// It is recommended to use `.instructions()` method to get an iterator over script
/// instructions and work with that instead.
///
/// ## Memory safety
///
/// The type is `#[repr(transparent)]` for internal purposes only!
/// No consumer crate may rely on the represenation of the struct!
///
/// ## References
///
///
/// ### Bitcoin Core References
///
/// * [CScript definition](https://github.com/bitcoin/bitcoin/blob/d492dc1cdaabdc52b0766bf4cba4bd73178325d0/src/script/script.h#L410)
///
#[derive(PartialOrd, Ord, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Script([u8]);

/// An owned, growable script.
///
/// `ScriptBuf` is the most common script type that has the ownership over the contents of the
/// script. It has a close relationship with its borrowed counterpart, [`Script`].
///
/// Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
/// that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
///
/// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
#[derive(Default, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptBuf(Vec<u8>);

impl ToOwned for Script {
    type Owned = ScriptBuf;

    fn to_owned(&self) -> Self::Owned {
        ScriptBuf(self.0.to_owned())
    }
}

impl Script {
    /// Treat byte slice as `Script`
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> &Script {
        // SAFETY: copied from `std`
        // The pointer was just created from a reference which is still alive.
        // Casting slice pointer to a transparent struct wrapping that slice is sound (same
        // layout).
        unsafe {
            &*(bytes as *const [u8] as *const Script)
        }
    }

    /// Treat mutable byte slice as `Script`
    #[inline]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Script {
        // SAFETY: copied from `std`
        // The pointer was just created from a reference which is still alive.
        // Casting slice pointer to a transparent struct wrapping that slice is sound (same
        // layout).
        // Function signature prevents callers from accessing `bytes` while the returned reference
        // is alive.
        unsafe {
            &mut *(bytes as *mut [u8] as *mut Script)
        }
    }

    /// Returns the script data as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the script data as a mutable byte slice.
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Creates a new empty script.
    #[inline]
    pub fn empty() -> &'static Script { Script::from_bytes(&[]) }

    /// Creates a new script builder
    pub fn builder() -> Builder {
      Builder::new()
    }

    /// Returns 160-bit hash of the script.
    #[inline]
    pub fn script_hash(&self) -> ScriptHash {
        ScriptHash::hash(self.as_bytes())
    }

    /// Returns 256-bit hash of the script for P2WSH outputs.
    #[inline]
    pub fn wscript_hash(&self) -> WScriptHash {
        WScriptHash::hash(self.as_bytes())
    }

    /// Computes leaf hash of tapscript.
    #[inline]
    pub fn tapscript_leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(self, LeafVersion::TapScript)
    }

    /// Returns the length in bytes of the script.
    #[inline]
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns whether the script is the empty script.
    #[inline]
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns a copy of the script data.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> { self.0.to_owned() }

    /// Returns an iterator over script bytes.
    #[inline]
    pub fn bytes(&self) -> Bytes<'_> {
        Bytes(self.as_bytes().iter().copied())
    }

    /// Computes the P2WSH output corresponding to this witnessScript (aka the "witness redeem
    /// script").
    #[inline]
    pub fn to_v0_p2wsh(&self) -> ScriptBuf {
        ScriptBuf::new_v0_p2wsh(&self.wscript_hash())
    }

    /// Computes P2TR output with a given internal key and a single script spending path equal to
    /// the current script, assuming that the script is a Tapscript.
    #[inline]
    pub fn to_v1_p2tr<C: Verification>(&self, secp: &Secp256k1<C>, internal_key: UntweakedPublicKey) -> ScriptBuf {
        let leaf_hash = self.tapscript_leaf_hash();
        let merkle_root = TapNodeHash::from(leaf_hash);
        ScriptBuf::new_v1_p2tr(secp, internal_key, Some(merkle_root))
    }

    /// Returns witness version of the script, if any, assuming the script is a `scriptPubkey`.
    #[inline]
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        self.0.first().and_then(|opcode| WitnessVersion::try_from(opcodes::All::from(*opcode)).ok())
    }

    /// Checks whether a script pubkey is a P2SH output.
    #[inline]
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == OP_HASH160.to_u8()
            && self.0[1] == OP_PUSHBYTES_20.to_u8()
            && self.0[22] == OP_EQUAL.to_u8()
    }

    /// Checks whether a script pubkey is a P2PKH output.
    #[inline]
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == OP_DUP.to_u8()
            && self.0[1] == OP_HASH160.to_u8()
            && self.0[2] == OP_PUSHBYTES_20.to_u8()
            && self.0[23] == OP_EQUALVERIFY.to_u8()
            && self.0[24] == OP_CHECKSIG.to_u8()
    }

    /// Checks whether a script pubkey is a P2PK output.
    ///
    /// You can obtain the public key, if its valid,
    /// by calling [`p2pk_public_key()`](Self::p2pk_public_key)
    #[inline]
    pub fn is_p2pk(&self) -> bool {
        self.p2pk_pubkey_bytes().is_some()
    }

    /// Returns the public key if this script is P2PK with a **valid** public key.
    ///
    /// This may return `None` even when [`is_p2pk()`](Self::is_p2pk) returns true.
    /// This happens when the public key is invalid (e.g. the point not being on the curve).
    /// It also implies the script is unspendable.
    #[inline]
    pub fn p2pk_public_key(&self) -> Option<PublicKey> {
        PublicKey::from_slice(self.p2pk_pubkey_bytes()?).ok()
    }

    /// Returns the bytes of the (possibly invalid) public key if this script is P2PK.
    #[inline]
    fn p2pk_pubkey_bytes(&self) -> Option<&[u8]> {
        match self.len() {
            67 if self.0[0] == OP_PUSHBYTES_65.to_u8()
                    && self.0[66] == OP_CHECKSIG.to_u8() =>  {
                Some(&self.0[1..66])
            }
            35 if self.0[0] == OP_PUSHBYTES_33.to_u8()
                    && self.0[34] == OP_CHECKSIG.to_u8() =>  {
                Some(&self.0[1..34])
            }
            _ => None
        }
    }

    /// Checks whether a script pubkey is a Segregated Witness (segwit) program.
    #[inline]
    pub fn is_witness_program(&self) -> bool {
        // A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of a 1-byte
        // push opcode (for 0 to 16) followed by a data push between 2 and 40 bytes gets a new
        // special meaning. The value of the first push is called the "version byte". The following
        // byte vector pushed is called the "witness program".
        let script_len = self.0.len();
        if !(4..=42).contains(&script_len) {
            return false
        }
        let ver_opcode = opcodes::All::from(self.0[0]); // Version 0 or PUSHNUM_1-PUSHNUM_16
        let push_opbyte = self.0[1]; // Second byte push opcode 2-40 bytes
        WitnessVersion::try_from(ver_opcode).is_ok()
            && push_opbyte >= OP_PUSHBYTES_2.to_u8()
            && push_opbyte <= OP_PUSHBYTES_40.to_u8()
            // Check that the rest of the script has the correct size
            && script_len - 2 == push_opbyte as usize
    }

    /// Checks whether a script pubkey is a P2WSH output.
    #[inline]
    pub fn is_v0_p2wsh(&self) -> bool {
        self.0.len() == 34
            && self.witness_version() == Some(WitnessVersion::V0)
            && self.0[1] == OP_PUSHBYTES_32.to_u8()
    }

    /// Checks whether a script pubkey is a P2WPKH output.
    #[inline]
    pub fn is_v0_p2wpkh(&self) -> bool {
        self.0.len() == 22
            && self.witness_version() == Some(WitnessVersion::V0)
            && self.0[1] == OP_PUSHBYTES_20.to_u8()
    }

    /// Checks whether a script pubkey is a P2TR output.
    #[inline]
    pub fn is_v1_p2tr(&self) -> bool {
        self.0.len() == 34
            && self.witness_version() == Some(WitnessVersion::V1)
            && self.0[1] == OP_PUSHBYTES_32.to_u8()
    }

    /// Check if this is an OP_RETURN output.
    #[inline]
    pub fn is_op_return (&self) -> bool {
        match self.0.first() {
            Some(b) => *b == OP_RETURN.to_u8(),
            None => false
        }
    }

    /// Checks whether a script can be proven to have no satisfying input.
    #[inline]
    pub fn is_provably_unspendable(&self) -> bool {
        use crate::blockdata::opcodes::Class::{ReturnOp, IllegalOp};

        match self.0.first() {
            Some(b) => {
                let first = opcodes::All::from(*b);
                let class = first.classify(opcodes::ClassifyContext::Legacy);

                class == ReturnOp || class == IllegalOp
            },
            None => false,
        }
    }

    /// Returns the minimum value an output with this script should have in order to be
    /// broadcastable on today's Bitcoin network.
    pub fn dust_value(&self) -> crate::Amount {
        // This must never be lower than Bitcoin Core's GetDustThreshold() (as of v0.21) as it may
        // otherwise allow users to create transactions which likely can never be broadcast/confirmed.
        let sats = DUST_RELAY_TX_FEE as u64 / 1000 * // The default dust relay fee is 3000 satoshi/kB (i.e. 3 sat/vByte)
        if self.is_op_return() {
            0
        } else if self.is_witness_program() {
            32 + 4 + 1 + (107 / 4) + 4 + // The spend cost copied from Core
            8 + // The serialized size of the TxOut's amount field
            self.consensus_encode(&mut sink()).expect("sinks don't error") as u64 // The serialized size of this script_pubkey
        } else {
            32 + 4 + 1 + 107 + 4 + // The spend cost copied from Core
            8 + // The serialized size of the TxOut's amount field
            self.consensus_encode(&mut sink()).expect("sinks don't error") as u64 // The serialized size of this script_pubkey
        };

        crate::Amount::from_sat(sats)
    }

    /// Iterates over the script instructions.
    ///
    /// Each returned item is a nested enum covering opcodes, datapushes and errors.
    /// At most one error will be returned and then the iterator will end. To instead iterate over
    /// the script as sequence of bytes call the [`bytes`](Self::bytes) method.
    ///
    /// To force minimal pushes, use [`instructions_minimal`](Self::instructions_minimal).
    #[inline]
    pub fn instructions(&self) -> Instructions {
        Instructions {
            data: self.0.iter(),
            enforce_minimal: false,
        }
    }

    /// Iterates over the script instructions while enforcing minimal pushes.
    ///
    /// This is similar to [`instructions`](Self::instructions) but an error is returned if a push
    /// is not minimal.
    #[inline]
    pub fn instructions_minimal(&self) -> Instructions {
        Instructions {
            data: self.0.iter(),
            enforce_minimal: true,
        }
    }

    /// Iterates over the script instructions and their indices.
    ///
    /// Unless the script contains an error, the returned item consists of an index pointing to the
    /// position in the script where the instruction begins and the decoded instruction - either an
    /// opcode or data push.
    ///
    /// To force minimal pushes, use [`Self::instruction_indices_minimal`].
    #[inline]
    pub fn instruction_indices(&self) -> InstructionIndices {
        InstructionIndices::from_instructions(self.instructions())
    }

    /// Iterates over the script instructions and their indices while enforcing minimal pushes.
    ///
    /// This is similar to [`instruction_indices`](Self::instruction_indices) but an error is
    /// returned if a push is not minimal.
    #[inline]
    pub fn instruction_indices_minimal(&self) -> InstructionIndices {
        InstructionIndices::from_instructions(self.instructions_minimal())
    }

    /// Shorthand for [`Self::verify_with_flags`] with flag [bitcoinconsensus::VERIFY_ALL].
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify (&self, index: usize, amount: crate::Amount, spending_tx: &[u8]) -> Result<(), Error> {
        self.verify_with_flags(index, amount, spending_tx, bitcoinconsensus::VERIFY_ALL)
    }

    /// Verifies spend of an input script.
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending_tx` - The transaction that attempts to spend the output holding this script.
    ///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL`] and similar.
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify_with_flags<F: Into<u32>>(&self, index: usize, amount: crate::Amount, spending_tx: &[u8], flags: F) -> Result<(), Error> {
        Ok(bitcoinconsensus::verify_with_flags (&self.0[..], amount.to_sat(), spending_tx, index, flags.into())?)
    }

    /// Writes the assembly decoding of the script to the formatter.
    pub fn fmt_asm(&self, f: &mut dyn fmt::Write) -> fmt::Result {
        bytes_to_asm_fmt(self.as_ref(), f)
    }

    /// Returns the assembly decoding of the script.
    pub fn to_asm_string(&self) -> String {
        let mut buf = String::new();
        self.fmt_asm(&mut buf).unwrap();
        buf
    }

    /// Formats the script as lower-case hex.
    ///
    /// This is a more convenient and performant way to write `format!("{:x}", script)`.
    /// For better performance you should generally prefer displaying the script but if `String` is
    /// required (this is common in tests) this method is can be used.
    pub fn to_hex_string(&self) -> String {
        self.as_bytes().to_lower_hex_string()
    }

    /// Returns the first opcode of the script (if there is any).
    pub fn first_opcode(&self) -> Option<opcodes::All> {
        self.as_bytes().first().copied().map(From::from)
    }

    /// Iterates the script to find the last opcode.
    ///
    /// Returns `None` is the instruction is data push or if the script is empty.
    fn last_opcode(&self) -> Option<opcodes::All> {
        match self.instructions().last() {
            Some(Ok(Instruction::Op(op))) => Some(op),
            _ => None,
        }
    }

    /// Converts a [`Box<Script>`](Box) into a [`ScriptBuf`] without copying or allocating.
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn into_script_buf(self: Box<Self>) -> ScriptBuf {
        let rw = Box::into_raw(self) as *mut [u8];
        // SAFETY: copied from `std`
        // The pointer was just created from a box without deallocating
        // Casting a transparent struct wrapping a slice to the slice pointer is sound (same
        // layout).
        let inner = unsafe { Box::from_raw(rw) };
        ScriptBuf(Vec::from(inner))
    }
}

impl<'a> From<&'a Script> for Box<Script> {
    fn from(value: &'a Script) -> Self {
        value.to_owned().into()
    }
}

impl<'a> From<&'a Script> for ScriptBuf {
    fn from(value: &'a Script) -> Self {
        value.to_owned()
    }
}

impl<'a> From<&'a Script> for Cow<'a, Script> {
    fn from(value: &'a Script) -> Self {
        Cow::Borrowed(value)
    }
}

impl<'a> From<&'a Script> for Arc<Script> {
    fn from(value: &'a Script) -> Self {
        let rw: *const [u8] = Arc::into_raw(Arc::from(&value.0));
        // SAFETY: copied from `std`
        // The pointer was just created from an Arc without deallocating
        // Casting a slice to a transparent struct wrapping that slice is sound (same
        // layout).
        unsafe { Arc::from_raw(rw as *const Script) }
    }
}

impl<'a> From<&'a Script> for Rc<Script> {
    fn from(value: &'a Script) -> Self {
        let rw: *const [u8] = Rc::into_raw(Rc::from(&value.0));
        // SAFETY: copied from `std`
        // The pointer was just created from an Rc without deallocating
        // Casting a slice to a transparent struct wrapping that slice is sound (same
        // layout).
        unsafe { Rc::from_raw(rw as *const Script) }
    }
}

/// Iterator over bytes of a script
pub struct Bytes<'a>(core::iter::Copied<core::slice::Iter<'a, u8>>);

impl Iterator for Bytes<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n)
    }
}

impl DoubleEndedIterator for Bytes<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n)
    }
}

impl ExactSizeIterator for Bytes<'_> {}
impl core::iter::FusedIterator for Bytes<'_> {}

macro_rules! delegate_index {
    ($($type:ty),* $(,)?) => {
        $(
            /// Script subslicing operation - read [slicing safety](#slicing-safety)!
            impl Index<$type> for Script {
                type Output = Self;

                #[inline]
                fn index(&self, index: $type) -> &Self::Output {
                    Self::from_bytes(&self.0[index])
                }
            }
        )*
    }
}

delegate_index!(Range<usize>, RangeFrom<usize>, RangeTo<usize>, RangeFull, RangeInclusive<usize>, RangeToInclusive<usize>);
#[cfg(rust_v_1_53)]
#[cfg_attr(docsrs, doc(cfg(rust_v_1_53)))]
delegate_index!((Bound<usize>, Bound<usize>));

impl AsRef<Script> for Script {
    #[inline]
    fn as_ref(&self) -> &Script {
        self
    }
}

impl AsMut<Script> for Script {
    fn as_mut(&mut self) -> &mut Script {
        self
    }
}

impl AsRef<[u8]> for Script {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for Script {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        self.fmt_asm(f)?;
        f.write_str(")")
    }
}

impl fmt::Display for Script {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_asm(f)
    }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl fmt::UpperHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl core::str::FromStr for ScriptBuf {
    type Err = hex::Error;
    #[inline]
    fn from_str(s: &str) -> Result<Self, hex::Error> {
        ScriptBuf::from_hex(s)
    }
}

impl fmt::Display for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_script(), f)
    }
}

impl fmt::LowerHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.as_script(), f)
    }
}

impl fmt::UpperHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(self.as_script(), f)
    }
}

/// An object which can be used to construct a script piece by piece.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder(ScriptBuf, Option<opcodes::All>);

impl fmt::Display for Builder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_asm(f)
    }
}

debug_from_display!(Builder);

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push; for more information see
    /// `https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Push_operators`
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
    /// Error validating the script with bitcoinconsensus library.
    #[cfg(feature = "bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    BitcoinConsensus(bitcoinconsensus::Error),
    /// Can not find the spent output.
    UnknownSpentOutput(OutPoint),
    /// Can not serialize the spending transaction.
    Serialization
}

// If bitcoinonsensus-std is off but bitcoinconsensus is present we patch the error type to
// implement `std::error::Error`.
#[cfg(all(feature = "std", feature = "bitcoinconsensus", not(feature = "bitcoinconsensus-std")))]
mod bitcoinconsensus_hack {
    use core::fmt;

    #[repr(transparent)]
    pub(crate) struct Error(bitcoinconsensus::Error);

    impl fmt::Debug for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, f)
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(&self.0, f)
        }
    }

    // bitcoinconsensus::Error has no sources at this time
    impl std::error::Error for Error {}

    pub(crate) fn wrap_error(error: &bitcoinconsensus::Error) -> &Error {
        // Unfortunately, we cannot have the reference inside `Error` struct because of the 'static
        // bound on `source` return type, so we have to use unsafe to overcome the limitation.
        // SAFETY: the type is repr(transparent) and the lifetimes match
        unsafe {
            &*(error as *const _ as *const Error)
        }
    }
}

#[cfg(not(all(feature = "std", feature = "bitcoinconsensus", not(feature = "bitcoinconsensus-std"))))]
mod bitcoinconsensus_hack {
    #[allow(unused_imports)] // conditionally used
    pub(crate) use core::convert::identity as wrap_error;
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "bitcoinconsensus")]
        use bitcoin_internals::write_err;

        match *self {
            Error::NonMinimalPush => f.write_str("non-minimal datapush"),
            Error::EarlyEndOfScript => f.write_str("unexpected end of script"),
            Error::NumericOverflow => f.write_str("numeric overflow (number on stack larger than 4 bytes)"),
            #[cfg(feature = "bitcoinconsensus")]
            Error::BitcoinConsensus(ref e) => write_err!(f, "bitcoinconsensus verification failed"; bitcoinconsensus_hack::wrap_error(e)),
            Error::UnknownSpentOutput(ref point) => write!(f, "unknown spent output: {}", point),
            Error::Serialization => f.write_str("can not serialize the spending transaction in Transaction::verify()"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            NonMinimalPush
            | EarlyEndOfScript
            | NumericOverflow
            | UnknownSpentOutput(_)
            | Serialization => None,
            #[cfg(feature = "bitcoinconsensus")]
            BitcoinConsensus(ref e) => Some(bitcoinconsensus_hack::wrap_error(e)),
        }
    }
}

// Our internal error proves that we only return these two cases from `read_uint_iter`.
// Since it's private we don't bother with trait impls besides From.
enum UintError {
    EarlyEndOfScript,
    NumericOverflow,
}

impl From<UintError> for Error {
    fn from(error: UintError) -> Self {
        match error {
            UintError::EarlyEndOfScript => Error::EarlyEndOfScript,
            UintError::NumericOverflow => Error::NumericOverflow,
        }
    }
}

#[cfg(feature = "bitcoinconsensus")]
#[doc(hidden)]
impl From<bitcoinconsensus::Error> for Error {
    fn from(err: bitcoinconsensus::Error) -> Error {
        Error::BitcoinConsensus(err)
    }
}

/// Encodes an integer in script(minimal CScriptNum) format.
///
/// Writes bytes into the buffer and returns the number of bytes written.
pub fn write_scriptint(out: &mut [u8; 8], n: i64) -> usize {
    let mut len = 0;
    if n == 0 { return len; }

    let neg = n < 0;

    let mut abs = n.unsigned_abs();
    while abs > 0xFF {
        out[len] = (abs & 0xFF) as u8;
        len += 1;
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        out[len] = abs as u8;
        len += 1;
        out[len] = if neg { 0x80u8 } else { 0u8 };
        len += 1;
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        out[len] = abs as u8;
        len += 1;
    }
    len
}

/// Decodes an integer in script(minimal CScriptNum) format.
///
/// Notice that this fails on overflow: the result is the same as in
/// bitcoind, that only 4-byte signed-magnitude values may be read as
/// numbers. They can be added or subtracted (and a long time ago,
/// multiplied and divided), and this may result in numbers which
/// can't be written out in 4 bytes or less. This is ok! The number
/// just can't be read as a number again.
/// This is a bit crazy and subtle, but it makes sense: you can load
/// 32-bit numbers and do anything with them, which back when mult/div
/// was allowed, could result in up to a 64-bit number. We don't want
/// overflow since that's surprising --- and we don't want numbers that
/// don't fit in 64 bits (for efficiency on modern processors) so we
/// simply say, anything in excess of 32 bits is no longer a number.
/// This is basically a ranged type implementation.
pub fn read_scriptint(v: &[u8]) -> Result<i64, Error> {
    let len = v.len();
    if len > 4 { return Err(Error::NumericOverflow); }
    let last = match v.last() {
        Some(last) => last,
        None => return Ok(0),
    };
    // Comment and code copied from Bitcoin Core:
    // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if (last & 0x7f) == 0 {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
            return Err(Error::NonMinimalPush);
        }
    }

    let (mut ret, sh) = v.iter()
                         .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[len - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    Ok(ret)
}

/// Decodes a boolean.
///
/// This is like "`read_scriptint` then map 0 to false and everything
/// else as true", except that the overflow rules don't apply.
#[inline]
pub fn read_scriptbool(v: &[u8]) -> bool {
    match v.split_last() {
        Some((last, rest)) => !((last & !0x80 == 0x00) && rest.iter().all(|&b| b == 0)),
        None => false,
    }
}

/// Decodes a script-encoded unsigned integer.
///
/// ## Errors
///
/// This function returns an error in these cases:
///
/// * `data` is shorter than `size` => `EarlyEndOfScript`
/// * `size` is greater than `u16::max_value / 8` (8191) => `NumericOverflow`
/// * The number being read overflows `usize` => `NumericOverflow`
///
/// Note that this does **not** return an error for `size` between `core::size_of::<usize>()`
/// and `u16::max_value / 8` if there's no overflow.
#[inline]
pub fn read_uint(data: &[u8], size: usize) -> Result<usize, Error> {
    read_uint_iter(&mut data.iter(), size).map_err(Into::into)
}

// We internally use implementation based on iterator so that it automatically advances as needed
// Errors are same as above, just different type.
fn read_uint_iter(data: &mut core::slice::Iter<'_, u8>, size: usize) -> Result<usize, UintError> {
    if data.len() < size {
        Err(UintError::EarlyEndOfScript)
    } else if size > usize::from(u16::max_value() / 8) {
        // Casting to u32 would overflow
        Err(UintError::NumericOverflow)
    } else {
        let mut ret = 0;
        for (i, item) in data.take(size).enumerate() {
            ret = usize::from(*item)
                // Casting is safe because we checked above to not repeat the same check in a loop
                .checked_shl((i * 8) as u32)
                .ok_or(UintError::NumericOverflow)?
                .checked_add(ret)
                .ok_or(UintError::NumericOverflow)?;
        }
        Ok(ret)
    }
}

/// Writes the assembly decoding of the script bytes to the formatter.
fn bytes_to_asm_fmt(script: &[u8], f: &mut dyn fmt::Write) -> fmt::Result {
    // This has to be a macro because it needs to break the loop
    macro_rules! read_push_data_len {
        ($iter:expr, $len:literal, $formatter:expr) => {
            match read_uint_iter($iter, $len) {
                Ok(n) => {
                    n
                },
                Err(UintError::EarlyEndOfScript) => {
                    $formatter.write_str("<unexpected end>")?;
                    break;
                }
                // We got the data in a slice which implies it being shorter than `usize::max_value()`
                // So if we got overflow, we can confidently say the number is higher than length of
                // the slice even though we don't know the exact number. This implies attempt to push
                // past end.
                Err(UintError::NumericOverflow) => {
                    $formatter.write_str("<push past end>")?;
                    break;
                }
            }
        }
    }

    let mut iter = script.iter();
    // Was at least one opcode emitted?
    let mut at_least_one = false;
    // `iter` needs to be borrowed in `read_push_data_len`, so we have to use `while let` instead
    // of `for`.
    while let Some(byte) = iter.next() {
        let opcode = opcodes::All::from(*byte);

        let data_len = if let opcodes::Class::PushBytes(n) = opcode.classify(opcodes::ClassifyContext::Legacy) {
            n as usize
        } else {
            match opcode {
                OP_PUSHDATA1 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 1, f)
                }
                OP_PUSHDATA2 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 2, f)
                }
                OP_PUSHDATA4 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 4, f)
                }
                _ => 0
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

impl ScriptBuf {
    /// Creates a new empty script.
    pub fn new() -> Self {
        ScriptBuf(Vec::new())
    }

    /// Creates a new empty script with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        ScriptBuf(Vec::with_capacity(capacity))
    }

    /// Pre-allocates at least `additional_len` bytes if needed.
    ///
    /// Reserves capacity for at least `additional_len` more bytes to be inserted in the given
    /// script. The script may reserve more space to speculatively avoid frequent reallocations.
    /// After calling `reserve`, capacity will be greater than or equal to
    /// `self.len() + additional_len`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    pub fn reserve(&mut self, additional_len: usize) {
        self.0.reserve(additional_len);
    }

    /// Pre-allocates exactly `additional_len` bytes if needed.
    ///
    /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
    /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
    /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
    ///
    /// Note that the allocator may give the collection more space than it requests. Therefore,
    /// capacity can not be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
    /// if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    pub fn reserve_exact(&mut self, additional_len: usize) {
        self.0.reserve_exact(additional_len);
    }

    /// Returns a reference to unsized script.
    pub fn as_script(&self) -> &Script {
        Script::from_bytes(&self.0)
    }

    /// Returns a mutable reference to unsized script.
    pub fn as_mut_script(&mut self) -> &mut Script {
        Script::from_bytes_mut(&mut self.0)
    }

    /// Creates a new script builder
    pub fn builder() -> Builder {
      Builder::new()
    }

    /// Generates P2PK-type of scriptPubkey.
    pub fn new_p2pk(pubkey: &PublicKey) -> Self {
        Builder::new()
            .push_key(pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2PKH-type of scriptPubkey.
    pub fn new_p2pkh(pubkey_hash: &PubkeyHash) -> Self {
        Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&pubkey_hash[..])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2sh(script_hash: &ScriptHash) -> Self {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(&script_hash[..])
            .push_opcode(OP_EQUAL)
            .into_script()
    }

    /// Generates P2WPKH-type of scriptPubkey.
    pub fn new_v0_p2wpkh(pubkey_hash: &WPubkeyHash) -> Self {
        // pubkey hash is 20 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V0, &pubkey_hash[..])
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_v0_p2wsh(script_hash: &WScriptHash) -> Self {
        // script hash is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V0, &script_hash[..])
    }

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree merkle root.
    pub fn new_v1_p2tr<C: Verification>(secp: &Secp256k1<C>, internal_key: UntweakedPublicKey, merkle_root: Option<TapNodeHash>) -> Self {
        let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V1, &output_key.serialize())
    }

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    pub fn new_v1_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V1, &output_key.serialize())
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
    pub fn new_witness_program(witness_program: &WitnessProgram) -> Self {
        Builder::new()
            .push_opcode(witness_program.version().into())
            .push_slice(witness_program.program())
            .into_script()
    }

    /// Generates P2WSH-type of scriptPubkey with a given [`WitnessVersion`] and the program bytes.
    /// Does not do any checks on version or program length.
    ///
    /// Convenience method used by `new_v0_p2wpkh`, `new_v0_p2wsh`, `new_v1_p2tr`, and
    /// `new_v1_p2tr_tweaked`.
    fn new_witness_program_unchecked(version: WitnessVersion, program: &[u8]) -> Self {
        debug_assert!(program.len() >= 2 && program.len() <= 40);
        // In segwit v0, the program must be 20 or 32 bytes long.
        debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
        Builder::new()
            .push_opcode(version.into())
            .push_slice(program)
            .into_script()
    }

    /// Generates OP_RETURN-type of scriptPubkey for the given data.
    pub fn new_op_return(data: &[u8]) -> Self {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(data)
            .into_script()
    }

    /// Creates a [`ScriptBuf`] from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::Error> {
        use crate::hashes::hex::FromHex;

        let v = Vec::from_hex(s)?;
        Ok(ScriptBuf::from_bytes(v))
    }

    /// Creates a [`ScriptBuf`] from a byte vector.
    ///
    /// This method doesn't (re)allocate.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        ScriptBuf(bytes)
    }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    pub fn into_bytes(self) -> Vec<u8> { self.0 }

    /// Computes the P2SH output corresponding to this redeem script.
    pub fn to_p2sh(&self) -> ScriptBuf {
        ScriptBuf::new_p2sh(&self.script_hash())
    }

    /// Returns the script code used for spending a P2WPKH output if this script is a script pubkey
    /// for a P2WPKH output. The `scriptCode` is described in [BIP143].
    ///
    /// [BIP143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>
    pub fn p2wpkh_script_code(&self) -> Option<ScriptBuf> {
        if !self.is_v0_p2wpkh() {
            return None
        }
        let script = Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&self.as_bytes()[2..]) // The `self` script is 0x00, 0x14, <pubkey_hash>
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();

        Some(script)
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, data: opcodes::All) {
        self.0.push(data.to_u8());
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// ## Panics
    ///
    /// The method panics if `data` length is greater or equal to 0x100000000.
    pub fn push_slice(&mut self, data: &[u8]) {
        self.reserve(Self::reserved_len_for_slice(data.len()));
        self.push_slice_no_opt(data);
    }

    /// Pushes the slice without reserving
    fn push_slice_no_opt(&mut self, data: &[u8]) {
        // Start with a PUSH opcode
        match data.len() as u64 {
            n if n < opcodes::Ordinary::OP_PUSHDATA1 as u64 => { self.0.push(n as u8); },
            n if n < 0x100 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA1.to_u8());
                self.0.push(n as u8);
            },
            n if n < 0x10000 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA2.to_u8());
                self.0.push((n % 0x100) as u8);
                self.0.push((n / 0x100) as u8);
            },
            n if n < 0x100000000 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA4.to_u8());
                self.0.push((n % 0x100) as u8);
                self.0.push(((n / 0x100) % 0x100) as u8);
                self.0.push(((n / 0x10000) % 0x100) as u8);
                self.0.push((n / 0x1000000) as u8);
            }
            _ => panic!("tried to put a 4bn+ sized object into a script!")
        }
        // Then push the raw bytes
        self.0.extend_from_slice(data);
    }

    /// Computes the sum of `len` and the lenght of an appropriate push opcode.
    fn reserved_len_for_slice(len: usize) -> usize {
        len + match len {
            0..=0x4b => 1,
            0x4c..=0xff => 2,
            0x100..=0xffff => 3,
            // we don't care about oversized, the other fn will panic anyway
            _ => 5,
        }
    }

    /// Add a single instruction to the script.
    ///
    /// ## Panics
    ///
    /// The method panics if the instruction is a data push with length greater or equal to
    /// 0x100000000.
    pub fn push_instruction(&mut self, instruction: Instruction<'_>) {
        match instruction {
            Instruction::Op(opcode) => self.push_opcode(opcode),
            Instruction::PushBytes(bytes) => self.push_slice(bytes),
        }
    }

    /// Like push_instruction, but avoids calling `reserve` to not re-check the length.
    pub fn push_instruction_no_opt(&mut self, instruction: Instruction<'_>) {
        match instruction {
            Instruction::Op(opcode) => self.push_opcode(opcode),
            Instruction::PushBytes(bytes) => self.push_slice_no_opt(bytes),
        }
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
    ///
    /// This function needs to iterate over the script to find the last instruction. Prefer
    /// `Builder` if you're creating the script from scratch or if you want to push `OP_VERIFY`
    /// multiple times.
    pub fn scan_and_push_verify(&mut self) {
        self.push_verify(self.last_opcode());
    }

    /// Adds an `OP_VERIFY` to the script or changes the most-recently-added opcode to `VERIFY`
    /// alternative.
    ///
    /// See the public fn [`Self::scan_and_push_verify`] to learn more.
    fn push_verify(&mut self, last_opcode: Option<opcodes::All>) {
        match opcode_to_verify(last_opcode) {
            Some(opcode) => {
                self.0.pop();
                self.push_opcode(opcode);
            },
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than lenght of the script but should not
    /// when they are equal. If you know beforehand that you need to create a script of exact size
    /// use [`reserve_exact`](Self::reserve_exact) before adding data to the script so that the
    /// reallocation can be avoided.
    #[must_use = "`self` will be dropped if the result is not used"]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script> {
        // Copied from PathBuf::into_boxed_path
        let rw = Box::into_raw(self.0.into_boxed_slice()) as *mut Script;
        unsafe { Box::from_raw(rw) }
    }
}

impl fmt::Debug for ScriptBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_script(), f)
    }
}

impl Deref for ScriptBuf {
    type Target = Script;

    fn deref(&self) -> &Self::Target {
        Script::from_bytes(&self.0)
    }
}

impl DerefMut for ScriptBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Script::from_bytes_mut(&mut self.0)
    }
}

impl Borrow<Script> for ScriptBuf {
    fn borrow(&self) -> &Script {
        self
    }
}

impl BorrowMut<Script> for ScriptBuf {
    fn borrow_mut(&mut self) -> &mut Script {
        self
    }
}

impl AsRef<Script> for ScriptBuf {
    fn as_ref(&self) -> &Script {
        self
    }
}

impl AsMut<Script> for ScriptBuf {
    fn as_mut(&mut self) -> &mut Script {
        self
    }
}

impl AsRef<[u8]> for ScriptBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for ScriptBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl From<Vec<u8>> for ScriptBuf {
    fn from(v: Vec<u8>) -> Self { ScriptBuf(v) }
}

impl From<ScriptBuf> for Vec<u8> {
    fn from(v: ScriptBuf) -> Self { v.0 }
}

impl From<ScriptBuf> for Box<Script> {
    fn from(v: ScriptBuf) -> Self {
        v.into_boxed_script()
    }
}

impl From<ScriptBuf> for Cow<'_, Script> {
    fn from(value: ScriptBuf) -> Self {
        Cow::Owned(value)
    }
}

impl<'a> From<Cow<'a, Script>> for ScriptBuf {
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned,
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a> From<Cow<'a, Script>> for Box<Script> {
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned.into(),
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl PartialEq<Script> for ScriptBuf {
    fn eq(&self, other: &Script) -> bool {
        self.as_script().eq(other)
    }
}

impl PartialOrd<Script> for ScriptBuf {
    fn partial_cmp(&self, other: &Script) -> Option<Ordering> {
        self.as_script().partial_cmp(other)
    }
}

impl PartialEq<ScriptBuf> for Script {
    fn eq(&self, other: &ScriptBuf) -> bool {
        self.eq(other.as_script())
    }
}

impl PartialOrd<ScriptBuf> for Script {
    fn partial_cmp(&self, other: &ScriptBuf) -> Option<Ordering> {
        self.partial_cmp(other.as_script())
    }
}

impl<'a> core::iter::FromIterator<Instruction<'a>> for ScriptBuf {
    fn from_iter<T>(iter: T) -> Self where T: IntoIterator<Item = Instruction<'a>> {
        let mut script = ScriptBuf::new();
        script.extend(iter);
        script
    }
}

impl<'a> Extend<Instruction<'a>> for ScriptBuf {
    fn extend<T>(&mut self, iter: T) where T: IntoIterator<Item = Instruction<'a>> {
        let iter = iter.into_iter();
        // Most of Bitcoin scripts have only a few opcodes, so we can avoid reallocations in many
        // cases.
        if iter.size_hint().1.map(|max| max < 6).unwrap_or(false) {
            let mut iter = iter.fuse();
            // `MaybeUninit` might be faster but we don't want to introduce more `unsafe` than
            // required.
            let mut head = [None; 5];
            let mut total_size = 0;
            for (head, instr) in head.iter_mut().zip(&mut iter) {
                total_size += instr.script_serialized_len();
                *head = Some(instr);
            }
            // Incorrect impl of `size_hint` breaks `Iterator` contract so we're free to panic.
            assert!(iter.next().is_none(), "Buggy implementation of `Iterator` on {} returns invalid upper bound", core::any::type_name::<T::IntoIter>());
            self.reserve(total_size);
            for instr in head.iter().cloned().flatten() {
                self.push_instruction_no_opt(instr);
            }
        } else {
            for instr in iter {
                self.push_instruction(instr);
            }
        }
    }
}

impl From<ScriptBuf> for ScriptHash {
    fn from(script: ScriptBuf) -> ScriptHash {
        script.script_hash()
    }
}

impl From<&ScriptBuf> for ScriptHash {
    fn from(script: &ScriptBuf) -> ScriptHash {
        script.script_hash()
    }
}

impl From<&Script> for ScriptHash {
    fn from(script: &Script) -> ScriptHash {
        script.script_hash()
    }
}

impl From<ScriptBuf> for WScriptHash {
    fn from(script: ScriptBuf) -> WScriptHash {
        script.wscript_hash()
    }
}

impl From<&ScriptBuf> for WScriptHash {
    fn from(script: &ScriptBuf) -> WScriptHash {
        script.wscript_hash()
    }
}

impl From<&Script> for WScriptHash {
    fn from(script: &Script) -> WScriptHash {
        script.wscript_hash()
    }
}

/// A "parsed opcode" which allows iterating over a [`Script`] in a more sensible way.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Instruction<'a> {
    /// Push a bunch of data.
    PushBytes(&'a [u8]),
    /// Some non-push opcode.
    Op(opcodes::All),
}

impl<'a> Instruction<'a> {
    /// Returns the opcode if the instruction is not a data push.
    pub fn opcode(&self) -> Option<opcodes::All> {
        match self {
            Instruction::Op(op) => Some(*op),
            Instruction::PushBytes(_) => None,
        }
    }

    /// Returns the opcode if the instruction is not a data push.
    pub fn push_bytes(&self) -> Option<&[u8]> {
        match self {
            Instruction::Op(_) => None,
            Instruction::PushBytes(bytes) => Some(bytes),
        }
    }

    /// Returns the number of bytes required to encode the instruction in script.
    fn script_serialized_len(&self) -> usize {
        match self {
            Instruction::Op(_) => 1,
            Instruction::PushBytes(bytes) => ScriptBuf::reserved_len_for_slice(bytes.len()),
        }
    }
}

/// Iterator over a script returning parsed opcodes.
#[derive(Debug, Clone)]
pub struct Instructions<'a> {
    data: core::slice::Iter<'a, u8>,
    enforce_minimal: bool,
}

impl<'a> Instructions<'a> {
    /// Views the remaining script as a slice.
    ///
    /// This is analogous to what [`core::str::Chars::as_str`] does.
    pub fn as_script(&self) -> &'a Script {
        Script::from_bytes(self.data.as_slice())
    }

    /// Sets the iterator to end so that it won't iterate any longer.
    fn kill(&mut self) {
        let len = self.data.len();
        self.data.nth(len.max(1) - 1);
    }

    /// Takes a `len` bytes long slice from iterator and returns it, advancing the iterator.
    ///
    /// If the iterator is not long enough [`Error::EarlyEndOfScript`] is returned and the iterator
    /// is killed to avoid returning an infinite stream of errors.
    fn take_slice_or_kill(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.data.len() >= len {
            let slice = &self.data.as_slice()[..len];
            if len > 0 {
                self.data.nth(len - 1);
            }

            Ok(slice)
        } else {
            self.kill();
            Err(Error::EarlyEndOfScript)
        }
    }

    fn next_push_data_len(&mut self, len: usize, min_push_len: usize) -> Option<Result<Instruction<'a>, Error>> {
        let n = match read_uint_iter(&mut self.data, len) {
            Ok(n) => n,
            // We do exhaustive matching to not forget to handle new variants if we extend
            // `UintError` type.
            // Overflow actually means early end of script (script is definitely shorter
            // than `usize::max_value()`)
            Err(UintError::EarlyEndOfScript) | Err(UintError::NumericOverflow) => {
                self.kill();
                return Some(Err(Error::EarlyEndOfScript));
            },
        };
        if self.enforce_minimal && n < min_push_len {
            self.kill();
            return Some(Err(Error::NonMinimalPush));
        }
        Some(self.take_slice_or_kill(n).map(Instruction::PushBytes))
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, Error>;

    fn next(&mut self) -> Option<Result<Instruction<'a>, Error>> {
        let &byte = self.data.next()?;

        // classify parameter does not really matter here since we are only using
        // it for pushes and nums
        match opcodes::All::from(byte).classify(opcodes::ClassifyContext::Legacy) {
            opcodes::Class::PushBytes(n) => {
                // make sure safety argument holds across refactorings
                let n: u32 = n;
                // casting is safe because we don't support 16-bit architectures
                let n = n as usize;

                let op_byte = self.data.as_slice().first();
                match (self.enforce_minimal, op_byte, n) {
                    (true, Some(&op_byte), 1) if op_byte == 0x81 || (op_byte > 0 && op_byte <= 16) => {
                        self.kill();
                        Some(Err(Error::NonMinimalPush))
                    },
                    (_, None, 0) => {
                        // the iterator is already empty, may as well use this information to avoid
                        // whole take_slice_or_kill function
                        Some(Ok(Instruction::PushBytes(&[])))
                    },
                    _ => {
                        Some(self.take_slice_or_kill(n).map(Instruction::PushBytes))
                    }
                }
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => {
                self.next_push_data_len(1, 76)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => {
                self.next_push_data_len(2, 0x100)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => {
                self.next_push_data_len(4, 0x10000)
            }
            // Everything else we can push right through
            _ => {
                Some(Ok(Instruction::Op(opcodes::All::from(byte))))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.data.len() == 0 {
            (0, Some(0))
        } else {
            // There will not be more instructions than bytes
            (1, Some(self.data.len()))
        }
    }
}

impl<'a> core::iter::FusedIterator for Instructions<'a> {}

/// Iterator over script instructions with their positions.
///
/// The returned indices can be used for slicing [`Script`] [safely](Script#slicing-safety).
///
/// This is analogous to [`core::str::CharIndices`].
#[derive(Debug, Clone)]
pub struct InstructionIndices<'a> {
    instructions: Instructions<'a>,
    pos: usize,
}

impl<'a> InstructionIndices<'a> {
    /// Views the remaining script as a slice.
    ///
    /// This is analogous to what [`core::str::Chars::as_str`] does.
    #[inline]
    pub fn as_script(&self) -> &'a Script {
        self.instructions.as_script()
    }

    /// Creates `Self` setting `pos` to 0.
    fn from_instructions(instructions: Instructions<'a>) -> Self {
        InstructionIndices {
            instructions,
            pos: 0,
        }
    }

    fn remaining_bytes(&self) -> usize {
        self.instructions.as_script().len()
    }

    /// Modifies the iterator using `next_fn` returning the next item.
    ///
    /// This generically computes the new position and maps the value to be returned from iterator
    /// method.
    fn next_with<F: FnOnce(&mut Self) -> Option<Result<Instruction<'a>, Error>>>(&mut self, next_fn: F) -> Option<<Self as Iterator>::Item> {
        let prev_remaining = self.remaining_bytes();
        let prev_pos = self.pos;
        let instruction = next_fn(self)?;
        // No underflow: there must be less remaining bytes now than previously
        let consumed = prev_remaining - self.remaining_bytes();
        // No overflow: sum will never exceed slice length which itself can't exceed `usize`
        self.pos += consumed;
        Some(instruction.map(move |instruction| (prev_pos, instruction)))
    }
}

impl<'a> Iterator for InstructionIndices<'a> {
    /// The `usize` in the tuple represents index at which the returned `Instruction` is located.
    type Item = Result<(usize, Instruction<'a>), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with(|this| this.instructions.next())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.instructions.size_hint()
    }

    // the override avoids computing pos multiple times
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.next_with(|this| this.instructions.nth(n))
    }
}

impl core::iter::FusedIterator for InstructionIndices<'_> {}

impl Builder {
    /// Creates a new empty script.
    pub fn new() -> Self {
        Builder(ScriptBuf::new(), None)
    }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    pub fn push_int(self, data: i64) -> Builder {
        // We can special-case -1, 1-16
        if data == -1 || (1..=16).contains(&data) {
            let opcode = opcodes::All::from(
                (data - 1 + opcodes::OP_TRUE.to_u8() as i64) as u8
            );
            self.push_opcode(opcode)
        }
        // We can also special-case zero
        else if data == 0 {
            self.push_opcode(opcodes::OP_FALSE)
        }
        // Otherwise encode it as data
        else { self.push_int_non_minimal(data) }
    }

    /// Adds instructions to push an integer onto the stack without optimization.
    ///
    /// This uses the explicit encoding regardless of the availability of dedicated opcodes.
    pub(super) fn push_int_non_minimal(self, data: i64) -> Builder {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, data);
        self.push_slice(&buf[..len])
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice(mut self, data: &[u8]) -> Builder {
        self.0.push_slice(data);
        self.1 = None;
        self
    }

    /// Adds instructions to push a public key onto the stack.
    pub fn push_key(self, key: &PublicKey) -> Builder {
        if key.compressed {
            self.push_slice(&key.inner.serialize()[..])
        } else {
            self.push_slice(&key.inner.serialize_uncompressed()[..])
        }
    }

    /// Adds instructions to push an XOnly public key onto the stack.
    pub fn push_x_only_key(self, x_only_key: &XOnlyPublicKey) -> Builder {
        self.push_slice(&x_only_key.serialize())
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(mut self, data: opcodes::All) -> Builder {
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
    pub fn push_verify(mut self) -> Builder {
        // "duplicated code" because we need to update `1` field
        match opcode_to_verify(self.1) {
            Some(opcode) => {
                (self.0).0.pop();
                self.push_opcode(opcode)
            },
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf {
        self.0
    }

    /// Converts the `Builder` into script bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into()
    }

    /// Returns the internal script
    pub fn as_script(&self) -> &Script {
        &self.0
    }

    /// Returns script bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn opcode_to_verify(opcode: Option<opcodes::All>) -> Option<opcodes::All> {
    opcode.and_then(|opcode| {
        match opcode {
            OP_EQUAL => Some(OP_EQUALVERIFY),
            OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
            OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
            OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
            _ => None,
        }
    })
}

impl Default for Builder {
    fn default() -> Builder { Builder::new() }
}

/// Creates a new builder from an existing vector.
impl From<Vec<u8>> for Builder {
    fn from(v: Vec<u8>) -> Builder {
        let script = ScriptBuf::from(v);
        let last_op = script.last_opcode();
        Builder(script, last_op)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for Script {
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for &'de Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            use crate::serde::de::Error;

            return Err(D::Error::custom("deserialization of `&Script` from human-readable formats is not possible"));
        }

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = &'de Script;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("borrowed bytes")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Script::from_bytes(v))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for ScriptBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;
        use crate::hashes::hex::FromHex;

        if deserializer.is_human_readable() {

            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = ScriptBuf;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let v = Vec::from_hex(v).map_err(E::custom)?;
                    Ok(ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_str(Visitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = ScriptBuf;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script Vec<u8>")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from(v.to_vec()))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_byte_buf(BytesVisitor)
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for ScriptBuf {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

impl Encodable for Script {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        crate::consensus::encode::consensus_encode_with_size(&self.0, w)
    }
}

impl Encodable for ScriptBuf {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ScriptBuf {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ScriptBuf(Decodable::consensus_decode_from_finite_reader(r)?))
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use super::*;
    use super::write_scriptint;

    use crate::hashes::hex::FromHex;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::blockdata::opcodes;
    use crate::crypto::key::PublicKey;
    use crate::psbt::serialize::Serialize;
    use crate::internal_macros::hex;

    #[test]
    fn script() {
        let mut comp = vec![];
        let mut script = Builder::new();
        assert_eq!(script.as_bytes(), &comp[..]);

        // small ints
        script = script.push_int(1);  comp.push(81u8); assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_int(0);  comp.push(0u8);  assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_int(4);  comp.push(84u8); assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_int(-1); comp.push(79u8); assert_eq!(script.as_bytes(), &comp[..]);
        // forced scriptint
        script = script.push_int_non_minimal(4); comp.extend([1u8, 4].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
        // big ints
        script = script.push_int(17); comp.extend([1u8, 17].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_int(10000); comp.extend([2u8, 16, 39].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
        // notice the sign bit set here, hence the extra zero/128 at the end
        script = script.push_int(10000000); comp.extend([4u8, 128, 150, 152, 0].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_int(-10000000); comp.extend([4u8, 128, 150, 152, 128].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);

        // data
        script = script.push_slice("NRA4VR".as_bytes()); comp.extend([6u8, 78, 82, 65, 52, 86, 82].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);

        // keys
        const KEYSTR1: &str = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        let key = PublicKey::from_str(&KEYSTR1[2..]).unwrap();
        script = script.push_key(&key); comp.extend_from_slice(&hex!(KEYSTR1)); assert_eq!(script.as_bytes(), &comp[..]);
        const KEYSTR2: &str = "41042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        let key = PublicKey::from_str(&KEYSTR2[2..]).unwrap();
        script = script.push_key(&key); comp.extend_from_slice(&hex!(KEYSTR2)); assert_eq!(script.as_bytes(), &comp[..]);

        // opcodes
        script = script.push_opcode(OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script.as_bytes(), &comp[..]);
        script = script.push_opcode(OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script.as_bytes(), &comp[..]);
    }

    #[test]
    fn p2pk_pubkey_bytes_valid_key_and_valid_script_returns_expected_key() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let p2pk = Script::builder().push_key(&key).push_opcode(OP_CHECKSIG).into_script();
        let actual = p2pk.p2pk_pubkey_bytes().unwrap();
        assert_eq!(actual.to_vec(), key.to_bytes());
    }

    #[test]
    fn p2pk_pubkey_bytes_no_checksig_returns_none() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let no_checksig = Script::builder().push_key(&key).into_script();
        assert_eq!(no_checksig.p2pk_pubkey_bytes(), None);
    }

    #[test]
    fn p2pk_pubkey_bytes_emptry_script_returns_none() {
        let empty_script = Script::builder().into_script();
        assert!(empty_script.p2pk_pubkey_bytes().is_none());
    }

    #[test]
    fn p2pk_pubkey_bytes_no_key_returns_none() {
        // scripts with no key should return None
        let no_push_bytes = Script::builder().push_opcode(OP_CHECKSIG).into_script();
        assert!(no_push_bytes.p2pk_pubkey_bytes().is_none());
    }

    #[test]
    fn p2pk_pubkey_bytes_different_op_code_returns_none() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let different_op_code = Script::builder().push_key(&key).push_opcode(OP_NOP).into_script();
        assert!(different_op_code.p2pk_pubkey_bytes().is_none());
    }

    #[test]
    fn p2pk_pubkey_bytes_incorrect_key_size_returns_none() {
        // 63 byte key
        let malformed_key = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1";
        let invalid_p2pk_script = Script::builder()
            .push_slice(malformed_key.as_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert!(invalid_p2pk_script.p2pk_pubkey_bytes().is_none());
    }

    #[test]
    fn p2pk_pubkey_bytes_invalid_key_returns_some() {
        let malformed_key = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1ux";
        let invalid_key_script = Script::builder()
            .push_slice(malformed_key.as_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert!(invalid_key_script.p2pk_pubkey_bytes().is_some());
    }

    #[test]
    fn p2pk_pubkey_bytes_compressed_key_returns_expected_key() {
        let compressed_key_str = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
        let key = PublicKey::from_str(compressed_key_str).unwrap();
        let p2pk = Script::builder().push_key(&key).push_opcode(OP_CHECKSIG).into_script();
        let actual = p2pk.p2pk_pubkey_bytes().unwrap();
        assert_eq!(actual.to_vec(), key.to_bytes());
    }

    #[test]
    fn p2pk_public_key_valid_key_and_valid_script_returns_expected_key() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let p2pk = Script::builder().push_key(&key).push_opcode(OP_CHECKSIG).into_script();
        let actual = p2pk.p2pk_public_key().unwrap();
        assert_eq!(actual, key);
    }

    #[test]
    fn p2pk_public_key_no_checksig_returns_none() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let no_checksig = Script::builder().push_key(&key).into_script();
        assert_eq!(no_checksig.p2pk_public_key(), None);
    }

    #[test]
    fn p2pk_public_key_empty_script_returns_none() {
        let empty_script = Script::builder().into_script();
        assert!(empty_script.p2pk_public_key().is_none());
    }

    #[test]
    fn p2pk_public_key_no_key_returns_none() {
        let no_push_bytes = Script::builder().push_opcode(OP_CHECKSIG).into_script();
        assert!(no_push_bytes.p2pk_public_key().is_none());
    }

    #[test]
    fn p2pk_public_key_different_op_code_returns_none() {
        let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        let key = PublicKey::from_str(key_str).unwrap();
        let different_op_code = Script::builder().push_key(&key).push_opcode(OP_NOP).into_script();
        assert!(different_op_code.p2pk_public_key().is_none());
    }

    #[test]
    fn p2pk_public_key_incorrect_size_returns_none() {
        let malformed_key = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1";
        let malformed_key_script = Script::builder()
            .push_slice(malformed_key.as_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert!(malformed_key_script.p2pk_public_key().is_none());

    }

    #[test]
    fn p2pk_public_key_invalid_key_returns_none() {
        let malformed_key = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1ux";
        let invalid_key_script = Script::builder()
            .push_slice(malformed_key.as_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert!(invalid_key_script.p2pk_public_key().is_none());
    }

    #[test]
    fn p2pk_public_key_compressed_key_returns_some() {
        let compressed_key_str = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
        let key = PublicKey::from_str(compressed_key_str).unwrap();
        let p2pk = Script::builder().push_key(&key).push_opcode(OP_CHECKSIG).into_script();
        let actual = p2pk.p2pk_public_key().unwrap();
        assert_eq!(actual, key);
    }

    #[test]
    fn script_x_only_key() {
        // Notice the "20" which prepends the keystr. That 20 is hexidecimal for "32". The Builder automatically adds the 32 opcode
        // to our script in order to give a heads up to the script compiler that it should add the next 32 bytes to the stack.
        // From: https://github.com/bitcoin-core/btcdeb/blob/e8c2750c4a4702768c52d15640ed03bf744d2601/doc/tapscript-example.md?plain=1#L43
        const KEYSTR: &str = "209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be";
        let x_only_key = XOnlyPublicKey::from_str(&KEYSTR[2..]).unwrap();
        let script = Builder::new().push_x_only_key(&x_only_key);
        assert_eq!(script.into_bytes(), hex!(KEYSTR));
    }

    #[test]
    fn script_builder() {
        // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
        let script = Builder::new().push_opcode(OP_DUP)
                                   .push_opcode(OP_HASH160)
                                   .push_slice(&hex!("16e1ae70ff0fa102905d4af297f6912bda6cce19"))
                                   .push_opcode(OP_EQUALVERIFY)
                                   .push_opcode(OP_CHECKSIG)
                                   .into_script();
        assert_eq!(script.to_hex_string(), "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac");
    }

    #[test]
    fn script_generators() {
        let pubkey = PublicKey::from_str("0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e").unwrap();
        assert!(ScriptBuf::new_p2pk(&pubkey).is_p2pk());

        let pubkey_hash = PubkeyHash::hash(&pubkey.inner.serialize());
        assert!(ScriptBuf::new_p2pkh(&pubkey_hash).is_p2pkh());

        let wpubkey_hash = WPubkeyHash::hash(&pubkey.inner.serialize());
        assert!(ScriptBuf::new_v0_p2wpkh(&wpubkey_hash).is_v0_p2wpkh());

        let script = Builder::new().push_opcode(OP_NUMEQUAL)
                                   .push_verify()
                                   .into_script();
        let script_hash = ScriptHash::hash(&script.serialize());
        let p2sh = ScriptBuf::new_p2sh(&script_hash);
        assert!(p2sh.is_p2sh());
        assert_eq!(script.to_p2sh(), p2sh);

        let wscript_hash = WScriptHash::hash(&script.serialize());
        let p2wsh = ScriptBuf::new_v0_p2wsh(&wscript_hash);
        assert!(p2wsh.is_v0_p2wsh());
        assert_eq!(script.to_v0_p2wsh(), p2wsh);

        // Test data are taken from the second output of
        // 2ccb3a1f745eb4eefcf29391460250adda5fab78aaddb902d25d3cd97d9d8e61 transaction
        let data = Vec::<u8>::from_hex("aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a").unwrap();
        let op_return = ScriptBuf::new_op_return(&data);
        assert!(op_return.is_op_return());
        assert_eq!(op_return.to_hex_string(), "6a24aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a");
    }

    #[test]
    fn script_builder_verify() {
        let simple = Builder::new()
            .push_verify()
            .into_script();
        assert_eq!(simple.to_hex_string(), "69");
        let simple2 = Builder::from(vec![])
            .push_verify()
            .into_script();
        assert_eq!(simple2.to_hex_string(), "69");

        let nonverify = Builder::new()
            .push_verify()
            .push_verify()
            .into_script();
        assert_eq!(nonverify.to_hex_string(), "6969");
        let nonverify2 = Builder::from(vec![0x69])
            .push_verify()
            .into_script();
        assert_eq!(nonverify2.to_hex_string(), "6969");

        let equal = Builder::new()
            .push_opcode(OP_EQUAL)
            .push_verify()
            .into_script();
        assert_eq!(equal.to_hex_string(), "88");
        let equal2 = Builder::from(vec![0x87])
            .push_verify()
            .into_script();
        assert_eq!(equal2.to_hex_string(), "88");

        let numequal = Builder::new()
            .push_opcode(OP_NUMEQUAL)
            .push_verify()
            .into_script();
        assert_eq!(numequal.to_hex_string(), "9d");
        let numequal2 = Builder::from(vec![0x9c])
            .push_verify()
            .into_script();
        assert_eq!(numequal2.to_hex_string(), "9d");

        let checksig = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .push_verify()
            .into_script();
        assert_eq!(checksig.to_hex_string(), "ad");
        let checksig2 = Builder::from(vec![0xac])
            .push_verify()
            .into_script();
        assert_eq!(checksig2.to_hex_string(), "ad");

        let checkmultisig = Builder::new()
            .push_opcode(OP_CHECKMULTISIG)
            .push_verify()
            .into_script();
        assert_eq!(checkmultisig.to_hex_string(), "af");
        let checkmultisig2 = Builder::from(vec![0xae])
            .push_verify()
            .into_script();
        assert_eq!(checkmultisig2.to_hex_string(), "af");

        let trick_slice = Builder::new()
            .push_slice(&[0xae]) // OP_CHECKMULTISIG
            .push_verify()
            .into_script();
        assert_eq!(trick_slice.to_hex_string(), "01ae69");
        let trick_slice2 = Builder::from(vec![0x01, 0xae])
            .push_verify()
            .into_script();
        assert_eq!(trick_slice2.to_hex_string(), "01ae69");
   }

    #[test]
    fn script_serialize() {
        let hex_script = hex!("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52");
        let script: Result<ScriptBuf, _> = deserialize(&hex_script);
        assert!(script.is_ok());
        assert_eq!(serialize(&script.unwrap()), hex_script);
    }

    #[test]
    fn scriptint_round_trip() {
        fn build_scriptint(n: i64) -> Vec<u8> {
            let mut buf = [0u8; 8];
            let len = write_scriptint(&mut buf, n);
            assert!(len <= 8);
            buf[..len].to_vec()
        }

        assert_eq!(build_scriptint(-1), vec![0x81]);
        assert_eq!(build_scriptint(255), vec![255, 0]);
        assert_eq!(build_scriptint(256), vec![0, 1]);
        assert_eq!(build_scriptint(257), vec![1, 1]);
        assert_eq!(build_scriptint(511), vec![255, 1]);
        let test_vectors = [
            10, 100, 255, 256, 1000, 10000, 25000, 200000, 5000000, 1000000000,
            (1 << 31) - 1, -((1 << 31) - 1),
        ];
        for &i in test_vectors.iter() {
            assert_eq!(Ok(i), read_scriptint(&build_scriptint(i)));
            assert_eq!(Ok(-i), read_scriptint(&build_scriptint(-i)));
        }
        assert!(read_scriptint(&build_scriptint(1 << 31)).is_err());
        assert!(read_scriptint(&build_scriptint(-(1 << 31))).is_err());
    }

    #[test]
    fn non_minimal_scriptints() {
        assert_eq!(read_scriptint(&[0x80, 0x00]), Ok(0x80));
        assert_eq!(read_scriptint(&[0xff, 0x00]), Ok(0xff));
        assert_eq!(read_scriptint(&[0x8f, 0x00, 0x00]), Err(Error::NonMinimalPush));
        assert_eq!(read_scriptint(&[0x7f, 0x00]), Err(Error::NonMinimalPush));
    }

    #[test]
    fn script_hashes() {
        let script = ScriptBuf::from_hex("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").unwrap();
        assert_eq!(script.script_hash().to_string(), "8292bcfbef1884f73c813dfe9c82fd7e814291ea");
        assert_eq!(script.wscript_hash().to_string(), "3e1525eb183ad4f9b3c5fa3175bdca2a52e947b135bbb90383bf9f6408e2c324");
	assert_eq!(
	    ScriptBuf::from_hex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac").unwrap().tapscript_leaf_hash().to_string(),
	    "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
	);
    }

    #[test]
    fn provably_unspendable_test() {
        // p2pk
        assert!(!ScriptBuf::from_hex("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").unwrap().is_provably_unspendable());
        assert!(!ScriptBuf::from_hex("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").unwrap().is_provably_unspendable());
        // p2pkhash
        assert!(!ScriptBuf::from_hex("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").unwrap().is_provably_unspendable());
        assert!(ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").unwrap().is_provably_unspendable());
    }

    #[test]
    fn op_return_test() {
        assert!(ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").unwrap().is_op_return());
        assert!(!ScriptBuf::from_hex("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").unwrap().is_op_return());
        assert!(!ScriptBuf::from_hex("").unwrap().is_op_return());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn script_json_serialize() {
        use serde_json;

        let original = ScriptBuf::from_hex("827651a0698faaa9a8a7a687").unwrap();
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json, serde_json::Value::String("827651a0698faaa9a8a7a687".to_owned()));
        let des = serde_json::from_value::<ScriptBuf>(json).unwrap();
        assert_eq!(original, des);
    }

    #[test]
    fn script_asm() {
        assert_eq!(ScriptBuf::from_hex("6363636363686868686800").unwrap().to_asm_string(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(ScriptBuf::from_hex("6363636363686868686800").unwrap().to_asm_string(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(ScriptBuf::from_hex("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac").unwrap().to_asm_string(),
                   "OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG");
        // Elements Alpha peg-out transaction with some signatures removed for brevity. Mainly to test PUSHDATA1
        assert_eq!(ScriptBuf::from_hex("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").unwrap().to_asm_string(),
                   "OP_0 OP_PUSHBYTES_71 304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401 OP_0 OP_PUSHDATA1 552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae");
        // Various weird scripts found in transaction 6d7ed9914625c73c0288694a6819196a27ef6c08f98e1270d975a8e65a3dc09a
        // which triggerred overflow bugs on 32-bit machines in script formatting in the past.
        assert_eq!(ScriptBuf::from_hex("01").unwrap().to_asm_string(),
                   "OP_PUSHBYTES_1 <push past end>");
        assert_eq!(ScriptBuf::from_hex("0201").unwrap().to_asm_string(),
                   "OP_PUSHBYTES_2 <push past end>");
        assert_eq!(ScriptBuf::from_hex("4c").unwrap().to_asm_string(),
                   "<unexpected end>");
        assert_eq!(ScriptBuf::from_hex("4c0201").unwrap().to_asm_string(),
                   "OP_PUSHDATA1 <push past end>");
        assert_eq!(ScriptBuf::from_hex("4d").unwrap().to_asm_string(),
                   "<unexpected end>");
        assert_eq!(ScriptBuf::from_hex("4dffff01").unwrap().to_asm_string(),
                   "OP_PUSHDATA2 <push past end>");
        assert_eq!(ScriptBuf::from_hex("4effffffff01").unwrap().to_asm_string(),
                   "OP_PUSHDATA4 <push past end>");
    }

    #[test]
    fn script_buf_collect() {
        assert_eq!(&core::iter::empty::<Instruction<'_>>().collect::<ScriptBuf>(), Script::empty());
        let script = ScriptBuf::from_hex("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").unwrap();
        assert_eq!(script.instructions().collect::<Result<ScriptBuf, _>>().unwrap(), script);
    }

    #[test]
    fn script_p2sh_p2p2k_template() {
        // random outputs I picked out of the mempool
        assert!(ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap().is_p2pkh());
        assert!(!ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap().is_p2sh());
        assert!(!ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ad").unwrap().is_p2pkh());
        assert!(!ScriptBuf::from_hex("").unwrap().is_p2pkh());
        assert!(ScriptBuf::from_hex("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").unwrap().is_p2sh());
        assert!(!ScriptBuf::from_hex("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").unwrap().is_p2pkh());
        assert!(!ScriptBuf::from_hex("a314acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").unwrap().is_p2sh());
    }

    #[test]
    fn script_p2pk() {
        assert!(ScriptBuf::from_hex("21021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51ac").unwrap().is_p2pk());
        assert!(ScriptBuf::from_hex("410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac").unwrap().is_p2pk());
    }

    #[test]
    fn p2sh_p2wsh_conversion() {
        // Test vectors taken from Core tests/data/script_tests.json
        // bare p2wsh
        let redeem_script = ScriptBuf::from_hex("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac").unwrap();
        let expected_witout = ScriptBuf::from_hex("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64").unwrap();
        assert!(redeem_script.to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);

        // p2sh
        let redeem_script = ScriptBuf::from_hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        let expected_p2shout = ScriptBuf::from_hex("a91491b24bf9f5288532960ac687abb035127b1d28a587").unwrap();
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert_eq!(redeem_script.to_p2sh(), expected_p2shout);

        // p2sh-p2wsh
        let redeem_script = ScriptBuf::from_hex("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac").unwrap();
        let expected_witout = ScriptBuf::from_hex("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64").unwrap();
        let expected_out = ScriptBuf::from_hex("a914f386c2ba255cc56d20cfa6ea8b062f8b5994551887").unwrap();
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert!(redeem_script.to_p2sh().to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);
        assert_eq!(redeem_script.to_v0_p2wsh().to_p2sh(), expected_out);
    }

    macro_rules! unwrap_all {
        ($($var:ident),*) => {
            $(
            let $var = $var.unwrap();
            )*
        }
    }

    #[test]
    fn test_iterator() {
        let zero = ScriptBuf::from_hex("00").unwrap();
        let zeropush = ScriptBuf::from_hex("0100").unwrap();

        let nonminimal = ScriptBuf::from_hex("4c0169b2").unwrap();      // PUSHDATA1 for no reason
        let minimal = ScriptBuf::from_hex("0169b2").unwrap();           // minimal
        let nonminimal_alt = ScriptBuf::from_hex("026900b2").unwrap();  // non-minimal number but minimal push (should be OK)

        let v_zero: Result<Vec<_>, Error> = zero.instruction_indices_minimal().collect();
        let v_zeropush: Result<Vec<_>, Error> = zeropush.instruction_indices_minimal().collect();

        let v_min: Result<Vec<_>, Error> = minimal.instruction_indices_minimal().collect();
        let v_nonmin: Result<Vec<_>, Error> = nonminimal.instruction_indices_minimal().collect();
        let v_nonmin_alt: Result<Vec<_>, Error> = nonminimal_alt.instruction_indices_minimal().collect();
        let slop_v_min: Result<Vec<_>, Error> = minimal.instruction_indices().collect();
        let slop_v_nonmin: Result<Vec<_>, Error> = nonminimal.instruction_indices().collect();
        let slop_v_nonmin_alt: Result<Vec<_>, Error> = nonminimal_alt.instruction_indices().collect();

        unwrap_all!(v_zero, v_zeropush, v_min, v_nonmin_alt, slop_v_min, slop_v_nonmin, slop_v_nonmin_alt);

        assert_eq!(v_zero, vec![(0, Instruction::PushBytes(&[]))]);
        assert_eq!(v_zeropush, vec![(0, Instruction::PushBytes(&[0]))]);

        assert_eq!(
            v_min,
            vec![(0, Instruction::PushBytes(&[105])), (2, Instruction::Op(opcodes::OP_NOP3))]
        );

        assert_eq!(v_nonmin.unwrap_err(), Error::NonMinimalPush);

        assert_eq!(
            v_nonmin_alt,
            vec![(0, Instruction::PushBytes(&[105, 0])), (3, Instruction::Op(opcodes::OP_NOP3))]
        );

        assert_eq!(v_min, slop_v_min);
        // indices must differ
        assert_ne!(v_min, slop_v_nonmin);
        // but the instructions must be equal
        for ((_, v_min_instr), (_, slop_v_nomin_instr)) in v_min.iter().zip(&slop_v_nonmin) {
            assert_eq!(v_min_instr, slop_v_nomin_instr);
        }
        assert_eq!(v_nonmin_alt, slop_v_nonmin_alt);
    }

	#[test]
    fn script_ord() {
        let script_1 = Builder::new().push_slice(&[1, 2, 3, 4]).into_script();
        let script_2 = Builder::new().push_int(10).into_script();
        let script_3 = Builder::new().push_int(15).into_script();
        let script_4 = Builder::new().push_opcode(OP_RETURN).into_script();

        assert!(script_1 < script_2);
        assert!(script_2 < script_3);
        assert!(script_3 < script_4);

        assert!(script_1 <= script_1);
        assert!(script_1 >= script_1);

        assert!(script_4 > script_3);
        assert!(script_3 > script_2);
        assert!(script_2 > script_1);
    }

	#[test]
	#[cfg(feature = "bitcoinconsensus")]
	fn test_bitcoinconsensus () {
		// a random segwit transaction from the blockchain using native segwit
		let spent = Builder::from(hex!("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d")).into_script();
		let spending = hex!("010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000");
		spent.verify(0, crate::Amount::from_sat(18393430), spending.as_slice()).unwrap();
	}

    #[test]
    fn defult_dust_value_tests() {
        // Check that our dust_value() calculator correctly calculates the dust limit on common
        // well-known scriptPubKey types.
        let script_p2wpkh = Builder::new().push_int(0).push_slice(&[42; 20]).into_script();
        assert!(script_p2wpkh.is_v0_p2wpkh());
        assert_eq!(script_p2wpkh.dust_value(), crate::Amount::from_sat(294));

        let script_p2pkh = Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&[42; 20])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert!(script_p2pkh.is_p2pkh());
        assert_eq!(script_p2pkh.dust_value(), crate::Amount::from_sat(546));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_script_serde_human_and_not() {
        let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);

        // Serialize
        let json = serde_json::to_string(&script).unwrap();
        assert_eq!(json, "\"000102\"");
        let bincode = bincode::serialize(&script).unwrap();
        assert_eq!(bincode, [3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]); // bincode adds u64 for length, serde_cbor use varint

        // Deserialize
        assert_eq!(script, serde_json::from_str::<ScriptBuf>(&json).unwrap());
        assert_eq!(script, bincode::deserialize::<ScriptBuf>(&bincode).unwrap());
    }

    #[test]
    fn test_instructions_are_fused() {
        let script = ScriptBuf::new();
        let mut instructions = script.instructions();
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
    }

    #[test]
    fn script_extend() {
        fn cmp_scripts(new_script: &Script, orig_script: &[Instruction<'_>]) {
            let mut new_instr = new_script.instructions();
            let mut orig_instr = orig_script.iter().cloned();
            for (new, orig) in new_instr.by_ref().zip(orig_instr.by_ref()) {
                assert_eq!(new.unwrap(), orig);
            }
            assert!(new_instr.next().is_none() && orig_instr.next().is_none())
        }

        let script_5_items = [
            Instruction::Op(OP_DUP),
            Instruction::Op(OP_HASH160),
            Instruction::PushBytes(&[42; 20]),
            Instruction::Op(OP_EQUALVERIFY),
            Instruction::Op(OP_CHECKSIG),
        ];
        let new_script = script_5_items.iter().cloned().collect::<ScriptBuf>();
        cmp_scripts(&new_script, &script_5_items);

        let script_6_items = [
            Instruction::Op(OP_DUP),
            Instruction::Op(OP_HASH160),
            Instruction::PushBytes(&[42; 20]),
            Instruction::Op(OP_EQUALVERIFY),
            Instruction::Op(OP_CHECKSIG),
            Instruction::Op(OP_NOP),
        ];
        let new_script = script_6_items.iter().cloned().collect::<ScriptBuf>();
        cmp_scripts(&new_script, &script_6_items);

        let script_7_items = [
            Instruction::Op(OP_DUP),
            Instruction::Op(OP_HASH160),
            Instruction::PushBytes(&[42; 20]),
            Instruction::Op(OP_EQUALVERIFY),
            Instruction::Op(OP_CHECKSIG),
            Instruction::Op(OP_NOP),
        ];
        let new_script = script_7_items.iter().cloned().collect::<ScriptBuf>();
        cmp_scripts(&new_script, &script_7_items);
    }

    #[test]
    fn read_scriptbool_zero_is_false() {
        let v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!read_scriptbool(&v));

        let v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x80]; // With sign bit set.
        assert!(!read_scriptbool(&v));
    }

    #[test]
    fn read_scriptbool_non_zero_is_true() {
        let v: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00];
        assert!(read_scriptbool(&v));

        let v: Vec<u8> = vec![0x01, 0x00, 0x00, 0x80]; // With sign bit set.
        assert!(read_scriptbool(&v));
    }
}
