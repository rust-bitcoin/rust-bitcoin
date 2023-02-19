// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

use core::convert::TryInto;
use crate::blockdata::opcodes;
use crate::blockdata::script::{read_uint_iter, Error, Script, ScriptBuf, UintError, PushBytes};

/// A "parsed opcode" which allows iterating over a [`Script`] in a more sensible way.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Instruction<'a> {
    /// Push a bunch of data.
    PushBytes(&'a PushBytes),
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

    /// Returns the pushed bytes if the instruction is a data push.
    pub fn push_bytes(&self) -> Option<&PushBytes> {
        match self {
            Instruction::Op(_) => None,
            Instruction::PushBytes(bytes) => Some(bytes),
        }
    }

    /// Returns the number of bytes required to encode the instruction in script.
    pub(super) fn script_serialized_len(&self) -> usize {
        match self {
            Instruction::Op(_) => 1,
            Instruction::PushBytes(bytes) => ScriptBuf::reserved_len_for_slice(bytes.len()),
        }
    }
}

/// Iterator over a script returning parsed opcodes.
#[derive(Debug, Clone)]
pub struct Instructions<'a> {
    pub(crate) data: core::slice::Iter<'a, u8>,
    pub(crate) enforce_minimal: bool,
}

impl<'a> Instructions<'a> {
    /// Views the remaining script as a slice.
    ///
    /// This is analogous to what [`core::str::Chars::as_str`] does.
    pub fn as_script(&self) -> &'a Script {
        Script::from_bytes(self.data.as_slice())
    }

    /// Sets the iterator to end so that it won't iterate any longer.
    pub(super) fn kill(&mut self) {
        let len = self.data.len();
        self.data.nth(len.max(1) - 1);
    }

    /// Takes a `len` bytes long slice from iterator and returns it, advancing the iterator.
    ///
    /// If the iterator is not long enough [`Error::EarlyEndOfScript`] is returned and the iterator
    /// is killed to avoid returning an infinite stream of errors.
    pub(super) fn take_slice_or_kill(&mut self, len: u32) -> Result<&'a PushBytes, Error> {
        let len = len as usize;
        if self.data.len() >= len {
            let slice = &self.data.as_slice()[..len];
            if len > 0 {
                self.data.nth(len - 1);
            }

            Ok(slice.try_into().expect("len was created from u32, so can't happen"))
        } else {
            self.kill();
            Err(Error::EarlyEndOfScript)
        }
    }

    pub(super) fn next_push_data_len(&mut self, len: PushDataLenLen, min_push_len: usize) -> Option<Result<Instruction<'a>, Error>> {
        let n = match read_uint_iter(&mut self.data, len as usize) {
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
        let result = n
            .try_into()
            .map_err(|_| Error::NumericOverflow)
            .and_then(|n| self.take_slice_or_kill(n))
            .map(Instruction::PushBytes);
        Some(result)
    }
}

/// Allowed length of push data length.
///
/// This makes it easier to prove correctness of `next_push_data_len`.
pub(super) enum PushDataLenLen {
    One = 1,
    Two = 2,
    Four = 4,
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

                let op_byte = self.data.as_slice().first();
                match (self.enforce_minimal, op_byte, n) {
                    (true, Some(&op_byte), 1) if op_byte == 0x81 || (op_byte > 0 && op_byte <= 16) => {
                        self.kill();
                        Some(Err(Error::NonMinimalPush))
                    },
                    (_, None, 0) => {
                        // the iterator is already empty, may as well use this information to avoid
                        // whole take_slice_or_kill function
                        Some(Ok(Instruction::PushBytes(PushBytes::empty())))
                    },
                    _ => {
                        Some(self.take_slice_or_kill(n).map(Instruction::PushBytes))
                    }
                }
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => {
                self.next_push_data_len(PushDataLenLen::One, 76)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => {
                self.next_push_data_len(PushDataLenLen::Two, 0x100)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => {
                self.next_push_data_len(PushDataLenLen::Four, 0x10000)
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
    pub(super) fn from_instructions(instructions: Instructions<'a>) -> Self {
        InstructionIndices {
            instructions,
            pos: 0,
        }
    }

    pub(super) fn remaining_bytes(&self) -> usize {
        self.instructions.as_script().len()
    }

    /// Modifies the iterator using `next_fn` returning the next item.
    ///
    /// This generically computes the new position and maps the value to be returned from iterator
    /// method.
    pub(super) fn next_with<F: FnOnce(&mut Self) -> Option<Result<Instruction<'a>, Error>>>(&mut self, next_fn: F) -> Option<<Self as Iterator>::Item> {
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
