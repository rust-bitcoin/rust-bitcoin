// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

use secp256k1::{Secp256k1, Verification};

use crate::address::{WitnessVersion, WitnessProgram};
use crate::blockdata::opcodes::{self, all::*};
use crate::blockdata::script::{opcode_to_verify, Builder, Instruction, Script, PushBytes};
use crate::hashes::hex;
use crate::hash_types::{PubkeyHash, WPubkeyHash, ScriptHash, WScriptHash};
use crate::key::{PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::prelude::*;
use crate::taproot::TapNodeHash;

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
pub struct ScriptBuf(pub(in crate::blockdata::script) Vec<u8>);

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
            .push_slice(pubkey_hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2sh(script_hash: &ScriptHash) -> Self {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(script_hash)
            .push_opcode(OP_EQUAL)
            .into_script()
    }

    /// Generates P2WPKH-type of scriptPubkey.
    pub fn new_v0_p2wpkh(pubkey_hash: &WPubkeyHash) -> Self {
        // pubkey hash is 20 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V0, pubkey_hash)
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_v0_p2wsh(script_hash: &WScriptHash) -> Self {
        // script hash is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V0, script_hash)
    }

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree merkle root.
    pub fn new_v1_p2tr<C: Verification>(secp: &Secp256k1<C>, internal_key: UntweakedPublicKey, merkle_root: Option<TapNodeHash>) -> Self {
        let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
    }

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    pub fn new_v1_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
        ScriptBuf::new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
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
    fn new_witness_program_unchecked<T: AsRef<PushBytes>>(version: WitnessVersion, program: T) -> Self {
        let program = program.as_ref();
        debug_assert!(program.len() >= 2 && program.len() <= 40);
        // In segwit v0, the program must be 20 or 32 bytes long.
        debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
        Builder::new()
            .push_opcode(version.into())
            .push_slice(program)
            .into_script()
    }

    /// Generates OP_RETURN-type of scriptPubkey for the given data.
    pub fn new_op_return<T: AsRef<PushBytes>>(data: &T) -> Self {
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

    /// Converts byte vector into script.
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
        self.v0_p2wpkh().map(|wpkh| {
            Builder::new()
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                // The `self` script is 0x00, 0x14, <pubkey_hash>
                .push_slice(wpkh)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        })
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, data: opcodes::All) {
        self.0.push(data.to_u8());
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice<T: AsRef<PushBytes>>(&mut self, data: T) {
        let data = data.as_ref();
        self.reserve(Self::reserved_len_for_slice(data.len()));
        self.push_slice_no_opt(data);
    }

    /// Pushes the slice without reserving
    fn push_slice_no_opt(&mut self, data: &PushBytes) {
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
        self.0.extend_from_slice(data.as_bytes());
    }

    /// Computes the sum of `len` and the lenght of an appropriate push opcode.
    pub(in crate::blockdata::script) fn reserved_len_for_slice(len: usize) -> usize {
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
    pub(in crate::blockdata::script) fn push_verify(&mut self, last_opcode: Option<opcodes::All>) {
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
