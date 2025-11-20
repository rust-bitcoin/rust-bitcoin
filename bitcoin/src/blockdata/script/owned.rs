// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

use hex::FromHex as _;
use internals::ToU64 as _;

use super::{
    opcode_to_verify, write_scriptint, Builder, Error, Instruction, PushBytes, ScriptBuf,
    ScriptExtPriv as _, ScriptPubKeyBuf,
};
use crate::key::{
    PubkeyHash, PublicKey, TapTweak, TweakedPublicKey, UntweakedPublicKey, WPubkeyHash,
};
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::prelude::Vec;
use crate::script::witness_program::{WitnessProgram, P2A_PROGRAM};
use crate::script::witness_version::WitnessVersion;
use crate::script::{self, ScriptHash, WScriptHash};
use crate::taproot::TapNodeHash;
use crate::{consensus, internal_macros};

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptBuf`] type.
    pub trait ScriptBufExt<T> impl<T> for ScriptBuf<T> {
        /// Constructs a new script builder
        fn builder() -> Builder<T> { Builder::new() }

        /// Adds instructions to push an integer onto the stack.
        ///
        /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
        /// opcodes to push some small integers.
        ///
        /// # Errors
        ///
        /// Only errors if `data == i32::MIN` (CScriptNum cannot have value -2^31).
        fn push_int(&mut self, n: i32) -> Result<(), Error> {
            if n == i32::MIN {
                // ref: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/script.h#L230
                Err(Error::NumericOverflow)
            } else {
                self.push_int_unchecked(n.into());
                Ok(())
            }
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
        fn push_int_unchecked(&mut self, n: i64) {
            match n {
                -1 => self.push_opcode(OP_1NEGATE),
                0 => self.push_opcode(OP_PUSHBYTES_0),
                1..=16 => self.push_opcode(Opcode::from(n as u8 + (OP_1.to_u8() - 1))),
                _ => self.push_int_non_minimal(n),
            }
        }

        /// Adds a single opcode to the script.
        fn push_opcode(&mut self, data: Opcode) { self.as_byte_vec().push(data.to_u8()); }

        /// Adds instructions to push some arbitrary data onto the stack.
        fn push_slice<D: AsRef<PushBytes>>(&mut self, data: D) {
            let bytes = data.as_ref().as_bytes();
            if bytes.len() == 1 && (bytes[0] == 0x81 || bytes[0] <= 16) {
                match bytes[0] {
                    0x81 => { self.push_opcode(OP_1NEGATE); },
                    0 => { self.push_opcode(OP_PUSHBYTES_0); },
                    1..=16 => { self.push_opcode(Opcode::from(bytes[0] + (OP_1.to_u8() - 1))); },
                    _ => {}, // unreachable arm
                }
            } else {
                self.push_slice_non_minimal(data);
            }
        }

        /// Adds instructions to push some arbitrary data onto the stack without minimality.
        ///
        /// Standardness rules require push minimality according to [CheckMinimalPush] of core.
        ///
        /// [CheckMinimalPush]: <https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.cpp#L366>
        fn push_slice_non_minimal<D: AsRef<PushBytes>>(&mut self, data: D) {
            let data = data.as_ref();
            self.reserve(Self::reserved_len_for_slice(data.len()));
            self.push_slice_no_opt(data);
        }

        /// Add a single instruction to the script.
        ///
        /// # Panics
        ///
        /// The method panics if the instruction is a data push with length greater or equal to
        /// 0x100000000.
        fn push_instruction(&mut self, instruction: Instruction<'_>) {
            match instruction {
                Instruction::Op(opcode) => self.push_opcode(opcode),
                Instruction::PushBytes(bytes) => self.push_slice(bytes),
            }
        }

        /// Like push_instruction, but avoids calling `reserve` to not re-check the length.
        fn push_instruction_no_opt(&mut self, instruction: Instruction<'_>) {
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
        fn scan_and_push_verify(&mut self) { self.push_verify(self.last_opcode()); }

        /// Constructs a new [`ScriptBuf`] from a hex string.
        ///
        /// The input string is expected to be consensus encoded i.e., includes the length prefix.
        fn from_hex_prefixed(s: &str) -> Result<Self, consensus::FromHexError>
            where Self: Sized
        {
            consensus::encode::deserialize_hex(s)
        }

        /// Constructs a new [`ScriptBuf`] from a hex string.
        #[deprecated(since = "TBD", note = "use `from_hex_no_length_prefix()` instead")]
        fn from_hex(s: &str) -> Result<Self, hex::HexToBytesError>
            where Self: Sized
        {
            Self::from_hex_no_length_prefix(s)
        }

        /// Constructs a new [`ScriptBuf`] from a hex string.
        ///
        /// This is **not** consensus encoding. If your hex string is a consensus encoded script
        /// then use `ScriptBuf::from_hex_prefixed`.
        fn from_hex_no_length_prefix(s: &str) -> Result<Self, hex::HexToBytesError>
            where Self: Sized
        {
            let v = Vec::from_hex(s)?;
            Ok(Self::from_bytes(v))
        }

        // This belongs only on RedeemScript and ScriptPubKey
        /// Generates P2WPKH-type of scriptPubkey.
        fn new_p2wpkh(pubkey_hash: WPubkeyHash) -> Self {
            // pubkey hash is 20 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
            script::new_witness_program_unchecked(WitnessVersion::V0, pubkey_hash)
        }

    }
}

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptPubKeyBuf`] type.
    pub trait ScriptPubKeyBufExt impl for ScriptPubKeyBuf {
        /// Generates OP_RETURN-type of scriptPubkey for the given data.
        fn new_op_return<T: AsRef<PushBytes>>(data: T) -> Self {
            Builder::new().push_opcode(OP_RETURN).push_slice(data).into_script()
        }

        /// Generates P2PK-type of scriptPubkey.
        fn new_p2pk(pubkey: PublicKey) -> Self {
            Builder::new().push_key(pubkey).push_opcode(OP_CHECKSIG).into_script()
        }

        /// Generates P2PKH-type of scriptPubkey.
        fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self {
            Builder::new()
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(pubkey_hash)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
                .into_script()
        }

        /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2sh(script_hash: ScriptHash) -> Self {
            Builder::new()
                .push_opcode(OP_HASH160)
                .push_slice(script_hash)
                .push_opcode(OP_EQUAL)
                .into_script()
        }

        /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
        fn new_p2wsh(script_hash: WScriptHash) -> Self {
            // script hash is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv0)
            script::new_witness_program_unchecked(WitnessVersion::V0, script_hash)
        }

        /// Generates P2TR for script spending path using an internal public key and some optional
        /// script tree Merkle root.
        fn new_p2tr<K: Into<UntweakedPublicKey>>(
            internal_key: K,
            merkle_root: Option<TapNodeHash>,
        ) -> Self {
            let internal_key = internal_key.into();
            let (output_key, _) = internal_key.tap_tweak(merkle_root);
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            script::new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
        }

        /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
        fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
            // output key is 32 bytes long, so it's safe to use `new_witness_program_unchecked` (Segwitv1)
            script::new_witness_program_unchecked(WitnessVersion::V1, output_key.serialize())
        }

        /// Generates pay to anchor output.
        fn new_p2a() -> Self {
            script::new_witness_program_unchecked(WitnessVersion::V1, P2A_PROGRAM)
        }

        /// Generates P2WSH-type of scriptPubkey with a given [`WitnessProgram`].
        fn new_witness_program(witness_program: &WitnessProgram) -> Self {
            use crate::script::witness_program::WitnessProgramExt;

            Builder::new()
                .push_opcode(witness_program.version().into())
                .push_slice(WitnessProgramExt::program(witness_program))
                .into_script()
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for super::ScriptBuf<T> {}
}

internal_macros::define_extension_trait! {
    pub(crate) trait ScriptBufExtPriv<T> impl<T> for ScriptBuf<T> {
        /// Pretends to convert `&mut ScriptBuf` to `&mut Vec<u8>` so that it can be modified.
        ///
        /// Note: if the returned value leaks the original `ScriptBuf` will become empty.
        fn as_byte_vec(&mut self) -> ScriptBufAsVec<'_, T> {
            let vec = core::mem::take(self).into_bytes();
            ScriptBufAsVec(self, vec)
        }

        /// Pushes the slice without reserving
        fn push_slice_no_opt(&mut self, data: &PushBytes) {
            let mut this = self.as_byte_vec();
            // Start with a PUSH opcode
            match data.len().to_u64() {
                n if n < opcodes::Ordinary::OP_PUSHDATA1 as u64 => {
                    this.push(n as u8);
                }
                n if n < 0x100 => {
                    this.push(opcodes::Ordinary::OP_PUSHDATA1.to_u8());
                    this.push(n as u8);
                }
                n if n < 0x10000 => {
                    this.push(opcodes::Ordinary::OP_PUSHDATA2.to_u8());
                    this.push((n % 0x100) as u8);
                    this.push((n / 0x100) as u8);
                }
                // `PushBytes` enforces len < 0x100000000
                n => {
                    this.push(opcodes::Ordinary::OP_PUSHDATA4.to_u8());
                    this.push((n % 0x100) as u8);
                    this.push(((n / 0x100) % 0x100) as u8);
                    this.push(((n / 0x10000) % 0x100) as u8);
                    this.push((n / 0x1000000) as u8);
                }
            }
            // Then push the raw bytes
            this.extend_from_slice(data.as_bytes());
        }

        /// Computes the sum of `len` and the length of an appropriate push opcode.
        fn reserved_len_for_slice(len: usize) -> usize {
            len + match len {
                0..=0x4b => 1,
                0x4c..=0xff => 2,
                0x100..=0xffff => 3,
                // we don't care about oversized, the other fn will panic anyway
                _ => 5,
            }
        }

        /// Adds an `OP_VERIFY` to the script or changes the most-recently-added opcode to `VERIFY`
        /// alternative.
        ///
        /// See the public fn [`Self::scan_and_push_verify`] to learn more.
        fn push_verify(&mut self, last_opcode: Option<Opcode>) {
            match opcode_to_verify(last_opcode) {
                Some(opcode) => {
                    self.as_byte_vec().pop();
                    self.push_opcode(opcode);
                }
                None => self.push_opcode(OP_VERIFY),
            }
        }

        /// Adds instructions to push an integer onto the stack without optimization.
        ///
        /// This uses the explicit encoding regardless of the availability of dedicated opcodes.
        fn push_int_non_minimal(&mut self, data: i64) {
            let mut buf = [0u8; 8];
            let len = write_scriptint(&mut buf, data);
            self.reserve(Self::reserved_len_for_slice(len));
            self.push_slice_no_opt(&<&PushBytes>::from(&buf)[..len]);
        }
    }
}

impl<'a, Tg> core::iter::FromIterator<Instruction<'a>> for ScriptBuf<Tg> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Instruction<'a>>,
    {
        let mut script = Self::new();
        script.extend(iter);
        script
    }
}

impl<'a, Tg> Extend<Instruction<'a>> for ScriptBuf<Tg> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Instruction<'a>>,
    {
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
            assert!(
                iter.next().is_none(),
                "Buggy implementation of `Iterator` on {} returns invalid upper bound",
                core::any::type_name::<T::IntoIter>()
            );
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

/// Pretends that this is a mutable reference to [`ScriptBuf`]'s internal buffer.
///
/// In reality the backing `Vec<u8>` is swapped with an empty one and this is holding both the
/// reference and the vec. The vec is put back when this drops so it also covers panics. (But not
/// leaks, which is OK since we never leak.)
pub(crate) struct ScriptBufAsVec<'a, T>(&'a mut ScriptBuf<T>, Vec<u8>);

impl<T> core::ops::Deref for ScriptBufAsVec<'_, T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target { &self.1 }
}

impl<T> core::ops::DerefMut for ScriptBufAsVec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.1 }
}

impl<T> Drop for ScriptBufAsVec<'_, T> {
    fn drop(&mut self) {
        let vec = core::mem::take(&mut self.1);
        *(self.0) = ScriptBuf::from_bytes(vec);
    }
}
