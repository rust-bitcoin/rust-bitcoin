// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid iff
//! the script leaves `TRUE` on the stack after being evaluated. Bitcoin's
//! script is a stack-based assembly language similar in spirit to Forth.
//!
//! This module provides the structures and functions needed to support scripts.
//!

use crate::prelude::*;

use crate::io;
use core::convert::TryFrom;
use core::{fmt, default::Default};
use core::ops::Index;
use crate::internal_macros::display_from_debug;

#[cfg(feature = "serde")] use serde;

use crate::hash_types::{PubkeyHash, WPubkeyHash, ScriptHash, WScriptHash};
use crate::blockdata::opcodes;
use crate::consensus::{encode, Decodable, Encodable};
use crate::hashes::{Hash, hex};
use crate::policy::DUST_RELAY_TX_FEE;
#[cfg(feature="bitcoinconsensus")] use bitcoinconsensus;
#[cfg(feature="bitcoinconsensus")] use core::convert::From;
use crate::OutPoint;

use crate::util::key::PublicKey;
use crate::util::address::WitnessVersion;
use crate::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash};
use secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use crate::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};

/// Bitcoin script.
///
/// A list of instructions in a simple, [Forth]-like, stack-based programming language
/// that Bitcoin uses.
///
/// [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
///
/// See [Bitcoin Wiki: Script][wiki-script] for more information.
///
/// [wiki-script]: https://en.bitcoin.it/wiki/Script
///
/// ### Bitcoin Core References
///
/// * [CScript definition](https://github.com/bitcoin/bitcoin/blob/d492dc1cdaabdc52b0766bf4cba4bd73178325d0/src/script/script.h#L410)
#[derive(Clone, Default, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Script(Box<[u8]>);

impl<I> Index<I> for Script
where
    [u8]: Index<I>,
{
    type Output = <[u8] as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}

impl hex::FromHex for Script {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item=Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Vec::from_byte_iter(iter).map(|v| Script(Box::<[u8]>::from(v)))
    }
}

impl core::str::FromStr for Script {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, hex::Error> {
        hex::FromHex::from_hex(s)
    }
}

/// An object which can be used to construct a script piece by piece.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Builder(Vec<u8>, Option<opcodes::All>);
display_from_debug!(Builder);

impl<I> Index<I> for Builder
where
    Vec<u8>: Index<I>,
{
    type Output = <Vec<u8> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push; for more information see
    /// `https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Push_operators`
    NonMinimalPush,
    /// Some opcode expected a parameter, but it was missing or truncated
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes
    NumericOverflow,
    /// Error validating the script with bitcoinconsensus library
    #[cfg(feature = "bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    BitcoinConsensus(bitcoinconsensus::Error),
    /// Can not find the spent output
    UnknownSpentOutput(OutPoint),
    /// Can not serialize the spending transaction
    Serialization
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            Error::NonMinimalPush => "non-minimal datapush",
            Error::EarlyEndOfScript => "unexpected end of script",
            Error::NumericOverflow => "numeric overflow (number on stack larger than 4 bytes)",
            #[cfg(feature = "bitcoinconsensus")]
            Error::BitcoinConsensus(ref _n) => "bitcoinconsensus verification failed",
            Error::UnknownSpentOutput(ref _point) => "unknown spent output Transaction::verify()",
            Error::Serialization => "can not serialize the spending transaction in Transaction::verify()",
        };
        f.write_str(str)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            NonMinimalPush
            | EarlyEndOfScript
            | NumericOverflow
            | UnknownSpentOutput(_)
            | Serialization => None,
            #[cfg(feature = "bitcoinconsensus")]
            BitcoinConsensus(_) => None,
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

/// Helper to encode an integer in script format.
/// Writes bytes into the buffer and returns the number of bytes written.
fn write_scriptint(out: &mut [u8; 8], n: i64) -> usize {
    let mut len = 0;
    if n == 0 { return len; }

    let neg = n < 0;

    let mut abs = if neg { -n } else { n } as usize;
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

/// Helper to decode an integer in script format
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
    if len == 0 { return Ok(0); }
    if len > 4 { return Err(Error::NumericOverflow); }

    let (mut ret, sh) = v.iter()
                         .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[len - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    Ok(ret)
}

/// This is like "`read_scriptint` then map 0 to false and everything
/// else as true", except that the overflow rules don't apply.
#[inline]
pub fn read_scriptbool(v: &[u8]) -> bool {
    match v.split_last() {
        Some((last, rest)) => !((last & !0x80 == 0x00) && rest.iter().all(|&b| b == 0)),
        None => false,
    }
}

/// Read a script-encoded unsigned integer
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

impl Script {
    /// Creates a new empty script.
    pub fn new() -> Script { Script(vec![].into_boxed_slice()) }

    /// Generates P2PK-type of scriptPubkey.
    pub fn new_p2pk(pubkey: &PublicKey) -> Script {
        Builder::new()
            .push_key(pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2PKH-type of scriptPubkey.
    pub fn new_p2pkh(pubkey_hash: &PubkeyHash) -> Script {
        Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&pubkey_hash[..])
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2sh(script_hash: &ScriptHash) -> Script {
        Builder::new()
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&script_hash[..])
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script()
    }

    /// Generates P2WPKH-type of scriptPubkey.
    #[deprecated(since = "0.28.0", note = "use Script::new_v0_p2wpkh method instead")]
    pub fn new_v0_wpkh(pubkey_hash: &WPubkeyHash) -> Script {
        Script::new_v0_p2wpkh(pubkey_hash)
    }

    /// Generates P2WPKH-type of scriptPubkey.
    pub fn new_v0_p2wpkh(pubkey_hash: &WPubkeyHash) -> Script {
        Script::new_witness_program(WitnessVersion::V0, &pubkey_hash[..])
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    #[deprecated(since = "0.28.0", note = "use Script::new_v0_p2wsh method instead")]
    pub fn new_v0_wsh(script_hash: &WScriptHash) -> Script {
        Script::new_v0_p2wsh(script_hash)
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_v0_p2wsh(script_hash: &WScriptHash) -> Script {
        Script::new_witness_program(WitnessVersion::V0, &script_hash[..])
    }

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree merkle root.
    pub fn new_v1_p2tr<C: Verification>(secp: &Secp256k1<C>, internal_key: UntweakedPublicKey, merkle_root: Option<TapBranchHash>) -> Script {
        let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);
        Script::new_witness_program(WitnessVersion::V1, &output_key.serialize())
    }

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    pub fn new_v1_p2tr_tweaked(output_key: TweakedPublicKey) -> Script {
        Script::new_witness_program(WitnessVersion::V1, &output_key.serialize())
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_witness_program(version: WitnessVersion, program: &[u8]) -> Script {
        Builder::new()
            .push_opcode(version.into())
            .push_slice(program)
            .into_script()
    }

    /// Generates OP_RETURN-type of scriptPubkey for the given data.
    pub fn new_op_return(data: &[u8]) -> Script {
        Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(data)
            .into_script()
    }

    /// Returns 160-bit hash of the script.
    pub fn script_hash(&self) -> ScriptHash {
        ScriptHash::hash(self.as_bytes())
    }

    /// Returns 256-bit hash of the script for P2WSH outputs.
    pub fn wscript_hash(&self) -> WScriptHash {
        WScriptHash::hash(self.as_bytes())
    }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns the script data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] { &*self.0 }

    /// Returns a copy of the script data.
    pub fn to_bytes(&self) -> Vec<u8> { self.0.clone().into_vec() }

    /// Converts the script into a byte vector.
    pub fn into_bytes(self) -> Vec<u8> { self.0.into_vec() }

    /// Computes the P2SH output corresponding to this redeem script.
    pub fn to_p2sh(&self) -> Script {
        Script::new_p2sh(&self.script_hash())
    }

    /// Returns the script code used for spending a P2WPKH output if this script is a script pubkey
    /// for a P2WPKH output. The `scriptCode` is described in [BIP143].
    ///
    /// [BIP143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>
    pub fn p2wpkh_script_code(&self) -> Option<Script> {
        if !self.is_v0_p2wpkh() {
            return None
        }
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&self[2..]) // The `self` script is 0x00, 0x14, <pubkey_hash>
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        Some(script)
    }

    /// Computes the P2WSH output corresponding to this witnessScript (aka the "witness redeem
    /// script").
    pub fn to_v0_p2wsh(&self) -> Script {
        Script::new_v0_p2wsh(&self.wscript_hash())
    }

    /// Computes P2TR output with a given internal key and a single script spending path equal to
    /// the current script, assuming that the script is a Tapscript.
    #[inline]
    pub fn to_v1_p2tr<C: Verification>(&self, secp: &Secp256k1<C>, internal_key: UntweakedPublicKey) -> Script {
        let leaf_hash = TapLeafHash::from_script(self, LeafVersion::TapScript);
        let merkle_root = TapBranchHash::from_inner(leaf_hash.into_inner());
        Script::new_v1_p2tr(secp, internal_key, Some(merkle_root))
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
            && self.0[0] == opcodes::all::OP_HASH160.to_u8()
            && self.0[1] == opcodes::all::OP_PUSHBYTES_20.to_u8()
            && self.0[22] == opcodes::all::OP_EQUAL.to_u8()
    }

    /// Checks whether a script pubkey is a P2PKH output.
    #[inline]
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == opcodes::all::OP_DUP.to_u8()
            && self.0[1] == opcodes::all::OP_HASH160.to_u8()
            && self.0[2] == opcodes::all::OP_PUSHBYTES_20.to_u8()
            && self.0[23] == opcodes::all::OP_EQUALVERIFY.to_u8()
            && self.0[24] == opcodes::all::OP_CHECKSIG.to_u8()
    }

    /// Checks whether a script pubkey is a P2PK output.
    #[inline]
    pub fn is_p2pk(&self) -> bool {
        match self.len() {
            67 => {
                self.0[0] == opcodes::all::OP_PUSHBYTES_65.to_u8()
                    && self.0[66] == opcodes::all::OP_CHECKSIG.to_u8()
            }
            35 => {
                self.0[0] == opcodes::all::OP_PUSHBYTES_33.to_u8()
                    && self.0[34] == opcodes::all::OP_CHECKSIG.to_u8()
            }
            _ => false
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
            && push_opbyte >= opcodes::all::OP_PUSHBYTES_2.to_u8()
            && push_opbyte <= opcodes::all::OP_PUSHBYTES_40.to_u8()
            // Check that the rest of the script has the correct size
            && script_len - 2 == push_opbyte as usize
    }

    /// Checks whether a script pubkey is a P2WSH output.
    #[inline]
    pub fn is_v0_p2wsh(&self) -> bool {
        self.0.len() == 34
            && self.witness_version() == Some(WitnessVersion::V0)
            && self.0[1] == opcodes::all::OP_PUSHBYTES_32.to_u8()
    }

    /// Checks whether a script pubkey is a P2WPKH output.
    #[inline]
    pub fn is_v0_p2wpkh(&self) -> bool {
        self.0.len() == 22
            && self.witness_version() == Some(WitnessVersion::V0)
            && self.0[1] == opcodes::all::OP_PUSHBYTES_20.to_u8()
    }

    /// Checks whether a script pubkey is a P2TR output.
    #[inline]
    pub fn is_v1_p2tr(&self) -> bool {
        self.0.len() == 34
            && self.witness_version() == Some(WitnessVersion::V1)
            && self.0[1] == opcodes::all::OP_PUSHBYTES_32.to_u8()
    }

    /// Check if this is an OP_RETURN output.
    pub fn is_op_return (&self) -> bool {
        match self.0.first() {
            Some(b) => *b == opcodes::all::OP_RETURN.to_u8(),
            None => false
        }
    }

    /// Checks whether a script can be proven to have no satisfying input.
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

    /// Iterates over the script in the form of `Instruction`s, which are an enum covering opcodes,
    /// datapushes and errors.
    ///
    /// At most one error will be returned and then the iterator will end. To instead iterate over
    /// the script as sequence of bytes, treat it as a slice using `script[..]` or convert it to a
    /// vector using `into_bytes()`.
    ///
    /// To force minimal pushes, use [`Self::instructions_minimal`].
    pub fn instructions(&self) -> Instructions {
        Instructions {
            data: self.0.iter(),
            enforce_minimal: false,
        }
    }

    /// Iterates over the script in the form of `Instruction`s while enforcing minimal pushes.
    pub fn instructions_minimal(&self) -> Instructions {
        Instructions {
            data: self.0.iter(),
            enforce_minimal: true,
        }
    }

    /// Shorthand for [`Self::verify_with_flags`] with flag [bitcoinconsensus::VERIFY_ALL].
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify (&self, index: usize, amount: crate::Amount, spending: &[u8]) -> Result<(), Error> {
        self.verify_with_flags(index, amount, spending, bitcoinconsensus::VERIFY_ALL)
    }

    /// Verifies spend of an input script.
    ///
    /// # Parameters
    ///  * `index` - The input index in spending which is spending this transaction.
    ///  * `amount` - The amount this script guards.
    ///  * `spending` - The transaction that attempts to spend the output holding this script.
    ///  * `flags` - Verification flags, see [`bitcoinconsensus::VERIFY_ALL`] and similar.
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify_with_flags<F: Into<u32>>(&self, index: usize, amount: crate::Amount, spending: &[u8], flags: F) -> Result<(), Error> {
        Ok(bitcoinconsensus::verify_with_flags (&self.0[..], amount.to_sat(), spending, index, flags.into())?)
    }

    /// Writes the assembly decoding of the script bytes to the formatter.
    pub fn bytes_to_asm_fmt(script: &[u8], f: &mut dyn fmt::Write) -> fmt::Result {
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
                    opcodes::all::OP_PUSHDATA1 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, 1, f)
                    }
                    opcodes::all::OP_PUSHDATA2 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, 2, f)
                    }
                    opcodes::all::OP_PUSHDATA4 => {
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
            if opcode == opcodes::all::OP_PUSHBYTES_0 {
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

    /// Writes the assembly decoding of the script to the formatter.
    pub fn fmt_asm(&self, f: &mut dyn fmt::Write) -> fmt::Result {
        Script::bytes_to_asm_fmt(self.as_ref(), f)
    }

    /// Creates an assembly decoding of the script in the given byte slice.
    pub fn bytes_to_asm(script: &[u8]) -> String {
        let mut buf = String::new();
        Script::bytes_to_asm_fmt(script, &mut buf).unwrap();
        buf
    }

    /// Returns the assembly decoding of the script.
    pub fn asm(&self) -> String {
        Script::bytes_to_asm(self.as_ref())
    }
}

/// Creates a new script from an existing vector.
impl From<Vec<u8>> for Script {
    fn from(v: Vec<u8>) -> Script { Script(v.into_boxed_slice()) }
}

/// A "parsed opcode" which allows iterating over a [`Script`] in a more sensible way.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Instruction<'a> {
    /// Push a bunch of data.
    PushBytes(&'a [u8]),
    /// Some non-push opcode.
    Op(opcodes::All),
}

/// Iterator over a script returning parsed opcodes.
pub struct Instructions<'a> {
    data: core::slice::Iter<'a, u8>,
    enforce_minimal: bool,
}

impl<'a> Instructions<'a> {
    /// Set the iterator to end so that it won't iterate any longer
    fn kill(&mut self) {
        let len = self.data.len();
        self.data.nth(len.max(1) - 1);
    }

    /// takes `len` bytes long slice from iterator and returns it advancing iterator
    /// if the iterator is not long enough [`Error::EarlyEndOfScript`] is returned and the iterator is killed
    /// to avoid returning an infinite stream of errors.
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
}

impl<'a> core::iter::FusedIterator for Instructions<'a> {}

impl Builder {
    /// Creates a new empty script.
    pub fn new() -> Self {
        Builder(vec![], None)
    }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack. Integers are
    /// encoded as little-endian signed-magnitude numbers, but there are
    /// dedicated opcodes to push some small integers.
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
        else { self.push_scriptint(data) }
    }

    /// Adds instructions to push an integer onto the stack, using the explicit
    /// encoding regardless of the availability of dedicated opcodes.
    pub fn push_scriptint(self, data: i64) -> Builder {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, data);
        self.push_slice(&buf[..len])
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice(mut self, data: &[u8]) -> Builder {
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
        self.0.extend(data.iter().cloned());
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
        self.0.push(data.to_u8());
        self.1 = Some(data);
        self
    }

    /// Adds an `OP_VERIFY` to the script, unless the most-recently-added
    /// opcode has an alternate `VERIFY` form, in which case that opcode
    /// is replaced e.g., `OP_CHECKSIG` will become `OP_CHECKSIGVERIFY`.
    pub fn push_verify(mut self) -> Builder {
        match self.1 {
            Some(opcodes::all::OP_EQUAL) => {
                self.0.pop();
                self.push_opcode(opcodes::all::OP_EQUALVERIFY)
            },
            Some(opcodes::all::OP_NUMEQUAL) => {
                self.0.pop();
                self.push_opcode(opcodes::all::OP_NUMEQUALVERIFY)
            },
            Some(opcodes::all::OP_CHECKSIG) => {
                self.0.pop();
                self.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            },
            Some(opcodes::all::OP_CHECKMULTISIG) => {
                self.0.pop();
                self.push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
            },
            _ => self.push_opcode(opcodes::all::OP_VERIFY),
        }
    }

    /// Converts the `Builder` into an unmodifiable `Script`.
    pub fn into_script(self) -> Script {
        Script(self.0.into_boxed_slice())
    }
}

impl Default for Builder {
    fn default() -> Builder { Builder::new() }
}

/// Creates a new builder from an existing vector.
impl From<Vec<u8>> for Builder {
    fn from(v: Vec<u8>) -> Builder {
        let script = Script(v.into_boxed_slice());
        let last_op = match script.instructions().last() {
            Some(Ok(Instruction::Op(op))) => Some(op),
            _ => None,
        };
        Builder(script.into_bytes(), last_op)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;
        use crate::hashes::hex::FromHex;

        if deserializer.is_human_readable() {

            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Script;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let v = Vec::from_hex(v).map_err(E::custom)?;
                    Ok(Script::from(v))
                }
            }
            deserializer.deserialize_str(Visitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = Script;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script Vec<u8>")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(Script::from(v.to_vec()))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(Script::from(v))
                }
            }
            deserializer.deserialize_bytes(BytesVisitor)
        }
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
        use crate::hashes::hex::ToHex;

        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

impl Encodable for Script {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Script {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Script(Decodable::consensus_decode_from_finite_reader(r)?))
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use super::*;
    use super::write_scriptint;

    use crate::hashes::hex::{FromHex, ToHex};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::blockdata::opcodes;
    use crate::util::key::PublicKey;
    use crate::util::psbt::serialize::Serialize;
    use crate::internal_macros::hex_script;

    #[test]
    fn script() {
        let mut comp = vec![];
        let mut script = Builder::new();
        assert_eq!(&script[..], &comp[..]);

        // small ints
        script = script.push_int(1);  comp.push(81u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(0);  comp.push(0u8);  assert_eq!(&script[..], &comp[..]);
        script = script.push_int(4);  comp.push(84u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-1); comp.push(79u8); assert_eq!(&script[..], &comp[..]);
        // forced scriptint
        script = script.push_scriptint(4); comp.extend([1u8, 4].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // big ints
        script = script.push_int(17); comp.extend([1u8, 17].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(10000); comp.extend([2u8, 16, 39].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // notice the sign bit set here, hence the extra zero/128 at the end
        script = script.push_int(10000000); comp.extend([4u8, 128, 150, 152, 0].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-10000000); comp.extend([4u8, 128, 150, 152, 128].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // data
        script = script.push_slice("NRA4VR".as_bytes()); comp.extend([6u8, 78, 82, 65, 52, 86, 82].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // keys
        let keystr = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        let key = PublicKey::from_str(&keystr[2..]).unwrap();
        script = script.push_key(&key); comp.extend(Vec::from_hex(keystr).unwrap().iter().cloned()); assert_eq!(&script[..], &comp[..]);
        let keystr = "41042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        let key = PublicKey::from_str(&keystr[2..]).unwrap();
        script = script.push_key(&key); comp.extend(Vec::from_hex(keystr).unwrap().iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // opcodes
        script = script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
        script = script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
    }

    #[test]
    fn script_x_only_key() {
        // Notice the "20" which prepends the keystr. That 20 is hexidecimal for "32". The Builder automatically adds the 32 opcode
        // to our script in order to give a heads up to the script compiler that it should add the next 32 bytes to the stack.
        // From: https://github.com/bitcoin-core/btcdeb/blob/e8c2750c4a4702768c52d15640ed03bf744d2601/doc/tapscript-example.md?plain=1#L43
        let keystr = "209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be";
        let x_only_key = XOnlyPublicKey::from_str(&keystr[2..]).unwrap();
        let script = Builder::new().push_x_only_key(&x_only_key);
        assert_eq!(script.0, Vec::from_hex(keystr).unwrap());
    }

    #[test]
    fn script_builder() {
        // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
        let script = Builder::new().push_opcode(opcodes::all::OP_DUP)
                                   .push_opcode(opcodes::all::OP_HASH160)
                                   .push_slice(&Vec::from_hex("16e1ae70ff0fa102905d4af297f6912bda6cce19").unwrap())
                                   .push_opcode(opcodes::all::OP_EQUALVERIFY)
                                   .push_opcode(opcodes::all::OP_CHECKSIG)
                                   .into_script();
        assert_eq!(script.to_hex(), "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac");
    }

    #[test]
    fn script_generators() {
        let pubkey = PublicKey::from_str("0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e").unwrap();
        assert!(Script::new_p2pk(&pubkey).is_p2pk());

        let pubkey_hash = PubkeyHash::hash(&pubkey.inner.serialize());
        assert!(Script::new_p2pkh(&pubkey_hash).is_p2pkh());

        let wpubkey_hash = WPubkeyHash::hash(&pubkey.inner.serialize());
        assert!(Script::new_v0_p2wpkh(&wpubkey_hash).is_v0_p2wpkh());

        let script = Builder::new().push_opcode(opcodes::all::OP_NUMEQUAL)
                                   .push_verify()
                                   .into_script();
        let script_hash = ScriptHash::hash(&script.serialize());
        let p2sh = Script::new_p2sh(&script_hash);
        assert!(p2sh.is_p2sh());
        assert_eq!(script.to_p2sh(), p2sh);

        let wscript_hash = WScriptHash::hash(&script.serialize());
        let p2wsh = Script::new_v0_p2wsh(&wscript_hash);
        assert!(p2wsh.is_v0_p2wsh());
        assert_eq!(script.to_v0_p2wsh(), p2wsh);

        // Test data are taken from the second output of
        // 2ccb3a1f745eb4eefcf29391460250adda5fab78aaddb902d25d3cd97d9d8e61 transaction
        let data = Vec::<u8>::from_hex("aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a").unwrap();
        let op_return = Script::new_op_return(&data);
        assert!(op_return.is_op_return());
        assert_eq!(op_return.to_hex(), "6a24aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a");
    }

    #[test]
    fn script_builder_verify() {
        let simple = Builder::new()
            .push_verify()
            .into_script();
        assert_eq!(simple.to_hex(), "69");
        let simple2 = Builder::from(vec![])
            .push_verify()
            .into_script();
        assert_eq!(simple2.to_hex(), "69");

        let nonverify = Builder::new()
            .push_verify()
            .push_verify()
            .into_script();
        assert_eq!(nonverify.to_hex(), "6969");
        let nonverify2 = Builder::from(vec![0x69])
            .push_verify()
            .into_script();
        assert_eq!(nonverify2.to_hex(), "6969");

        let equal = Builder::new()
            .push_opcode(opcodes::all::OP_EQUAL)
            .push_verify()
            .into_script();
        assert_eq!(equal.to_hex(), "88");
        let equal2 = Builder::from(vec![0x87])
            .push_verify()
            .into_script();
        assert_eq!(equal2.to_hex(), "88");

        let numequal = Builder::new()
            .push_opcode(opcodes::all::OP_NUMEQUAL)
            .push_verify()
            .into_script();
        assert_eq!(numequal.to_hex(), "9d");
        let numequal2 = Builder::from(vec![0x9c])
            .push_verify()
            .into_script();
        assert_eq!(numequal2.to_hex(), "9d");

        let checksig = Builder::new()
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_verify()
            .into_script();
        assert_eq!(checksig.to_hex(), "ad");
        let checksig2 = Builder::from(vec![0xac])
            .push_verify()
            .into_script();
        assert_eq!(checksig2.to_hex(), "ad");

        let checkmultisig = Builder::new()
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_verify()
            .into_script();
        assert_eq!(checkmultisig.to_hex(), "af");
        let checkmultisig2 = Builder::from(vec![0xae])
            .push_verify()
            .into_script();
        assert_eq!(checkmultisig2.to_hex(), "af");

        let trick_slice = Builder::new()
            .push_slice(&[0xae]) // OP_CHECKMULTISIG
            .push_verify()
            .into_script();
        assert_eq!(trick_slice.to_hex(), "01ae69");
        let trick_slice2 = Builder::from(vec![0x01, 0xae])
            .push_verify()
            .into_script();
        assert_eq!(trick_slice2.to_hex(), "01ae69");
   }

    #[test]
    fn script_serialize() {
        let hex_script = Vec::from_hex("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52").unwrap();
        let script: Result<Script, _> = deserialize(&hex_script);
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
    fn script_hashes() {
        let script = hex_script!("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac");
        assert_eq!(script.script_hash().to_hex(), "8292bcfbef1884f73c813dfe9c82fd7e814291ea");
        assert_eq!(script.wscript_hash().to_hex(), "3e1525eb183ad4f9b3c5fa3175bdca2a52e947b135bbb90383bf9f6408e2c324");
    }

    #[test]
    fn provably_unspendable_test() {
        // p2pk
        assert!(!hex_script!("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").is_provably_unspendable());
        assert!(!hex_script!("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").is_provably_unspendable());
        // p2pkhash
        assert!(!hex_script!("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").is_provably_unspendable());
        assert!(hex_script!("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").is_provably_unspendable());
    }

    #[test]
    fn op_return_test() {
        assert!(hex_script!("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").is_op_return());
        assert!(!hex_script!("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").is_op_return());
        assert!(!hex_script!("").is_op_return());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn script_json_serialize() {
        use serde_json;

        let original = hex_script!("827651a0698faaa9a8a7a687");
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json, serde_json::Value::String("827651a0698faaa9a8a7a687".to_owned()));
        let des = serde_json::from_value(json).unwrap();
        assert_eq!(original, des);
    }

    #[test]
    fn script_asm() {
        assert_eq!(hex_script!("6363636363686868686800").asm(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(hex_script!("6363636363686868686800").asm(),
                   "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0");
        assert_eq!(hex_script!("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac").asm(),
                   "OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG");
        // Elements Alpha peg-out transaction with some signatures removed for brevity. Mainly to test PUSHDATA1
        assert_eq!(hex_script!("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").asm(),
                   "OP_0 OP_PUSHBYTES_71 304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401 OP_0 OP_PUSHDATA1 552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae");
        // Various weird scripts found in transaction 6d7ed9914625c73c0288694a6819196a27ef6c08f98e1270d975a8e65a3dc09a
        // which triggerred overflow bugs on 32-bit machines in script formatting in the past.
        assert_eq!(hex_script!("01").asm(),
                   "OP_PUSHBYTES_1 <push past end>");
        assert_eq!(hex_script!("0201").asm(),
                   "OP_PUSHBYTES_2 <push past end>");
        assert_eq!(hex_script!("4c").asm(),
                   "<unexpected end>");
        assert_eq!(hex_script!("4c0201").asm(),
                   "OP_PUSHDATA1 <push past end>");
        assert_eq!(hex_script!("4d").asm(),
                   "<unexpected end>");
        assert_eq!(hex_script!("4dffff01").asm(),
                   "OP_PUSHDATA2 <push past end>");
        assert_eq!(hex_script!("4effffffff01").asm(),
                   "OP_PUSHDATA4 <push past end>");
    }

    #[test]
    fn script_p2sh_p2p2k_template() {
        // random outputs I picked out of the mempool
        assert!(hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").is_p2pkh());
        assert!(!hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").is_p2sh());
        assert!(!hex_script!("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ad").is_p2pkh());
        assert!(!hex_script!("").is_p2pkh());
        assert!(hex_script!("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2sh());
        assert!(!hex_script!("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2pkh());
        assert!(!hex_script!("a314acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87").is_p2sh());
    }

    #[test]
    fn script_p2pk() {
        assert!(hex_script!("21021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51ac").is_p2pk());
        assert!(hex_script!("410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac").is_p2pk());
    }

    #[test]
    fn p2sh_p2wsh_conversion() {
        // Test vectors taken from Core tests/data/script_tests.json
        // bare p2wsh
        let redeem_script = hex_script!("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac");
        let expected_witout = hex_script!("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64");
        assert!(redeem_script.to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);

        // p2sh
        let redeem_script = hex_script!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        let expected_p2shout = hex_script!("a91491b24bf9f5288532960ac687abb035127b1d28a587");
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert_eq!(redeem_script.to_p2sh(), expected_p2shout);

        // p2sh-p2wsh
        let redeem_script = hex_script!("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac");
        let expected_witout = hex_script!("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64");
        let expected_out = hex_script!("a914f386c2ba255cc56d20cfa6ea8b062f8b5994551887");
        assert!(redeem_script.to_p2sh().is_p2sh());
        assert!(redeem_script.to_p2sh().to_v0_p2wsh().is_v0_p2wsh());
        assert_eq!(redeem_script.to_v0_p2wsh(), expected_witout);
        assert_eq!(redeem_script.to_v0_p2wsh().to_p2sh(), expected_out);
    }

    #[test]
    fn test_iterator() {
        let zero = hex_script!("00");
        let zeropush = hex_script!("0100");

        let nonminimal = hex_script!("4c0169b2");      // PUSHDATA1 for no reason
        let minimal = hex_script!("0169b2");           // minimal
        let nonminimal_alt = hex_script!("026900b2");  // non-minimal number but minimal push (should be OK)

        let v_zero: Result<Vec<Instruction>, Error> = zero.instructions_minimal().collect();
        let v_zeropush: Result<Vec<Instruction>, Error> = zeropush.instructions_minimal().collect();

        let v_min: Result<Vec<Instruction>, Error> = minimal.instructions_minimal().collect();
        let v_nonmin: Result<Vec<Instruction>, Error> = nonminimal.instructions_minimal().collect();
        let v_nonmin_alt: Result<Vec<Instruction>, Error> = nonminimal_alt.instructions_minimal().collect();
        let slop_v_min: Result<Vec<Instruction>, Error> = minimal.instructions().collect();
        let slop_v_nonmin: Result<Vec<Instruction>, Error> = nonminimal.instructions().collect();
        let slop_v_nonmin_alt: Result<Vec<Instruction>, Error> = nonminimal_alt.instructions().collect();

        assert_eq!(v_zero.unwrap(), vec![Instruction::PushBytes(&[])]);
        assert_eq!(v_zeropush.unwrap(), vec![Instruction::PushBytes(&[0])]);

        assert_eq!(
            v_min.clone().unwrap(),
            vec![Instruction::PushBytes(&[105]), Instruction::Op(opcodes::OP_NOP3)]
        );

        assert_eq!(v_nonmin.err().unwrap(), Error::NonMinimalPush);

        assert_eq!(
            v_nonmin_alt.clone().unwrap(),
            vec![Instruction::PushBytes(&[105, 0]), Instruction::Op(opcodes::OP_NOP3)]
        );

        assert_eq!(v_min.clone().unwrap(), slop_v_min.unwrap());
        assert_eq!(v_min.unwrap(), slop_v_nonmin.unwrap());
        assert_eq!(v_nonmin_alt.unwrap(), slop_v_nonmin_alt.unwrap());
    }

	#[test]
    fn script_ord() {
        let script_1 = Builder::new().push_slice(&[1, 2, 3, 4]).into_script();
        let script_2 = Builder::new().push_int(10).into_script();
        let script_3 = Builder::new().push_int(15).into_script();
        let script_4 = Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script();

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
		let spent = Builder::from(Vec::from_hex("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d").unwrap()).into_script();
		let spending = Vec::from_hex("010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000").unwrap();
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
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&[42; 20])
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(script_p2pkh.is_p2pkh());
        assert_eq!(script_p2pkh.dust_value(), crate::Amount::from_sat(546));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_script_serde_human_and_not() {
        let script = Script::from(vec![0u8, 1u8, 2u8]);

        // Serialize
        let json = serde_json::to_string(&script).unwrap();
        assert_eq!(json, "\"000102\"");
        let bincode = bincode::serialize(&script).unwrap();
        assert_eq!(bincode, [3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]); // bincode adds u64 for length, serde_cbor use varint

        // Deserialize
        assert_eq!(script, serde_json::from_str(&json).unwrap());
        assert_eq!(script, bincode::deserialize(&bincode).unwrap());
    }

    #[test]
    fn test_instructions_are_fused() {
        let script = Script::new();
        let mut instructions = script.instructions();
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
        assert!(instructions.next().is_none());
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

