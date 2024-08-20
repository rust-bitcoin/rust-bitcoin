// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

use hex::FromHex;
use internals::ToU64 as _;

use super::{opcode_to_verify, Builder, Instruction, PushBytes, Script, ScriptExtPriv as _};
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::prelude::{Box, Vec};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

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
    #[inline]
    pub const fn new() -> Self { ScriptBuf(Vec::new()) }

    /// Creates a new empty script with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self { ScriptBuf(Vec::with_capacity(capacity)) }

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
    pub fn reserve(&mut self, additional_len: usize) { self.0.reserve(additional_len); }

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
    pub fn reserve_exact(&mut self, additional_len: usize) { self.0.reserve_exact(additional_len); }

    /// Returns a reference to unsized script.
    pub fn as_script(&self) -> &Script { Script::from_bytes(&self.0) }

    /// Returns a mutable reference to unsized script.
    pub fn as_mut_script(&mut self) -> &mut Script { Script::from_bytes_mut(&mut self.0) }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate.
    pub fn from_bytes(bytes: Vec<u8>) -> Self { ScriptBuf(bytes) }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    pub fn into_bytes(self) -> Vec<u8> { self.0 }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than length of the script but should not
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

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`ScriptBuf`] type.
    pub trait ScriptBufExt impl for ScriptBuf {
        /// Creates a new script builder
        fn builder() -> Builder { Builder::new() }

        /// Generates OP_RETURN-type of scriptPubkey for the given data.
        fn new_op_return<T: AsRef<PushBytes>>(data: T) -> Self {
            Builder::new().push_opcode(OP_RETURN).push_slice(data).into_script()
        }

        /// Creates a [`ScriptBuf`] from a hex string.
        fn from_hex(s: &str) -> Result<ScriptBuf, hex::HexToBytesError> {
            let v = Vec::from_hex(s)?;
            Ok(ScriptBuf::from_bytes(v))
        }

        /// Adds a single opcode to the script.
        fn push_opcode(&mut self, data: Opcode) { self.as_byte_vec().push(data.to_u8()); }

        /// Adds instructions to push some arbitrary data onto the stack.
        fn push_slice<T: AsRef<PushBytes>>(&mut self, data: T) {
            let data = data.as_ref();
            self.reserve(ScriptBuf::reserved_len_for_slice(data.len()));
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
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ScriptBuf {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = Vec::<u8>::arbitrary(u)?;
        Ok(ScriptBuf(v))
    }
}

crate::internal_macros::define_extension_trait! {
    pub(crate) trait ScriptBufExtPriv impl for ScriptBuf {
        /// Pretends to convert `&mut ScriptBuf` to `&mut Vec<u8>` so that it can be modified.
        ///
        /// Note: if the returned value leaks the original `ScriptBuf` will become empty.
        fn as_byte_vec(&mut self) -> ScriptBufAsVec<'_> {
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

/// Pretends that this is a mutable reference to [`ScriptBuf`]'s internal buffer.
///
/// In reality the backing `Vec<u8>` is swapped with an empty one and this is holding both the
/// reference and the vec. The vec is put back when this drops so it also covers paics. (But not
/// leaks, which is OK since we never leak.)
pub(crate) struct ScriptBufAsVec<'a>(&'a mut ScriptBuf, Vec<u8>);

impl<'a> core::ops::Deref for ScriptBufAsVec<'a> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target { &self.1 }
}

impl<'a> core::ops::DerefMut for ScriptBufAsVec<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.1 }
}

impl<'a> Drop for ScriptBufAsVec<'a> {
    fn drop(&mut self) {
        let vec = core::mem::take(&mut self.1);
        *(self.0) = ScriptBuf::from_bytes(vec);
    }
}
