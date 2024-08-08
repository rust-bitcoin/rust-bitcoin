// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

use primitives::script::ScriptBuf;

use super::{opcode_to_verify, Builder, Instruction, PushBytes};
use crate::internal_macros::define_extension_trait;
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::script;

define_extension_trait! {
    /// Extension functionality for the [`ScriptBuf`] type.
    pub trait ScriptBufExt impl for ScriptBuf {
        /// Creates a new script builder
        fn builder() -> Builder { Builder::new() }

        /// Generates OP_RETURN-type of scriptPubkey for the given data.
        fn new_op_return(data: impl AsRef<PushBytes>) -> Self {
            Builder::new().push_opcode(OP_RETURN).push_slice(data).into_script()
        }

        /// Adds a single opcode to the script.
        fn push_opcode(self: &mut Self, data: Opcode) { self.push(data.to_u8()); }

        /// Adds instructions to push some arbitrary data onto the stack.
        fn push_slice(self: &mut Self, data: impl AsRef<PushBytes>) {
            let data = data.as_ref();
            self.reserve(reserved_script_buf_len_for_slice(data.len()));
            push_slice_no_opt(self, data);
        }

        /// Add a single instruction to the script.
        ///
        /// # Panics
        ///
        /// The method panics if the instruction is a data push with length greater or equal to
        /// 0x100000000.
        fn push_instruction(self: &mut Self, instruction: Instruction<'_>) {
            match instruction {
                Instruction::Op(opcode) => self.push_opcode(opcode),
                Instruction::PushBytes(bytes) => self.push_slice(bytes),
            }
        }

        /// Like push_instruction, but avoids calling `reserve` to not re-check the length.
        fn push_instruction_no_opt(self: &mut Self, instruction: Instruction<'_>) {
            match instruction {
                Instruction::Op(opcode) => self.push_opcode(opcode),
                Instruction::PushBytes(bytes) => push_slice_no_opt(self, bytes),
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
        fn scan_and_push_verify(self: &mut Self) { push_verify(self, script::last_opcode(self)); }
    }
}

/// Pushes the slice without reserving
fn push_slice_no_opt(script: &mut ScriptBuf, data: &PushBytes) {
    // Start with a PUSH opcode
    match data.len() as u64 {
        n if n < opcodes::Ordinary::OP_PUSHDATA1 as u64 => {
            script.push(n as u8);
        }
        n if n < 0x100 => {
            script.push(opcodes::Ordinary::OP_PUSHDATA1.to_u8());
            script.push(n as u8);
        }
        n if n < 0x10000 => {
            script.push(opcodes::Ordinary::OP_PUSHDATA2.to_u8());
            script.push((n % 0x100) as u8);
            script.push((n / 0x100) as u8);
        }
        n => {
            // `PushBytes` enforces len < 0x100000000
            script.push(opcodes::Ordinary::OP_PUSHDATA4.to_u8());
            script.push((n % 0x100) as u8);
            script.push(((n / 0x100) % 0x100) as u8);
            script.push(((n / 0x10000) % 0x100) as u8);
            script.push((n / 0x1000000) as u8);
        }
    }
    // Then push the raw bytes
    script.extend_from_slice(data.as_bytes());
}

/// Computes the sum of `len` and the length of an appropriate push opcode.
pub(in crate::blockdata::script) fn reserved_script_buf_len_for_slice(len: usize) -> usize {
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
fn push_verify(script: &mut ScriptBuf, last_opcode: Option<Opcode>) {
    match opcode_to_verify(last_opcode) {
        Some(opcode) => {
            script.pop();
            script.push_opcode(opcode);
        }
        None => script.push_opcode(OP_VERIFY),
    }
}

impl<'a> core::iter::FromIterator<Instruction<'a>> for ScriptBuf {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Instruction<'a>>,
    {
        let mut script = ScriptBuf::new();
        script.extend(iter);
        script
    }
}

impl<'a> Extend<Instruction<'a>> for ScriptBuf {
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
