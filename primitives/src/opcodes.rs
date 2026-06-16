// SPDX-License-Identifier: CC0-1.0

//! Bitcoin script opcodes.
//!
//! Bitcoin's script uses a stack-based assembly language. This module defines
//! all of the opcodes for that language.

#![allow(non_camel_case_types)]

#[cfg(feature = "alloc")]
use core::fmt;

/// A script opcode.
///
/// We do not implement `Ord` on this type because there is no natural ordering on opcodes, but there
/// may appear to be one (e.g. because all the push opcodes appear in a consecutive block) and we
/// don't want to encourage subtly buggy code.
///
/// <details>
///   <summary>Example of Core bug caused by assuming ordering</summary>
///
///   Bitcoin Core's `IsPushOnly` considers `OP_RESERVED` to be a "push code", allowing this opcode
///   in contexts where only pushes are supposed to be allowed.
/// </details>
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Opcode {
    code: u8,
}

impl Opcode {
    /// Encodes [`Opcode`] as a byte.
    #[inline]
    pub const fn to_u8(self) -> u8 { self.code }

    /// Constructs an [`Opcode`] from a byte.
    #[inline]
    pub const fn from_u8(b: u8) -> Self { Self { code: b } }
}

impl From<u8> for Opcode {
    #[inline]
    fn from(b: u8) -> Self { Self::from_u8(b) }
}

impl From<Opcode> for u8 {
    #[inline]
    fn from(op: Opcode) -> Self { op.to_u8() }
}

macro_rules! all_opcodes {
    ($($op:ident => $val:expr, $doc:expr);* $(;)?) => {
        /// Enables wildcard imports to bring into scope all opcodes and nothing else.
        ///
        /// The `all` module is provided so one can use a wildcard import `use primitives::opcodes::all::*`
        /// to get all the `OP_FOO` opcodes without getting other types defined in `opcodes` (e.g. `Opcode`).
        ///
        /// This module is guaranteed to never contain anything except opcode constants and all opcode
        /// constants are guaranteed to begin with `OP_`.
        pub mod all {
            use super::Opcode;
            $(
                #[doc = $doc]
                pub const $op: Opcode = Opcode::from_u8($val);
            )*
        }
    }
}

all_opcodes! {
    OP_1NEGATE => 0x4f, "Push the array `0x81` onto the stack.";
    OP_1 => 0x51, "Push the array `0x01` onto the stack.";
    OP_2 => 0x52, "Push the array `0x02` onto the stack.";
    OP_3 => 0x53, "Push the array `0x03` onto the stack.";
    OP_4 => 0x54, "Push the array `0x04` onto the stack.";
    OP_5 => 0x55, "Push the array `0x05` onto the stack.";
    OP_6 => 0x56, "Push the array `0x06` onto the stack.";
    OP_7 => 0x57, "Push the array `0x07` onto the stack.";
    OP_8 => 0x58, "Push the array `0x08` onto the stack.";
    OP_9 => 0x59, "Push the array `0x09` onto the stack.";
    OP_10 => 0x5a, "Push the array `0x0a` onto the stack.";
    OP_11 => 0x5b, "Push the array `0x0b` onto the stack.";
    OP_12 => 0x5c, "Push the array `0x0c` onto the stack.";
    OP_13 => 0x5d, "Push the array `0x0d` onto the stack.";
    OP_14 => 0x5e, "Push the array `0x0e` onto the stack.";
    OP_15 => 0x5f, "Push the array `0x0f` onto the stack.";
    OP_16 => 0x60, "Push the array `0x10` onto the stack.";
    OP_NOP => 0x61, "Does nothing.";
    OP_IF => 0x63, "Pop and execute the next statements if a nonzero element was popped.";
    OP_NOTIF => 0x64, "Pop and execute the next statements if a zero element was popped.";
    OP_ELSE => 0x67, "Execute statements if those after the previous `OP_IF` were not, and vice-versa. \
             If there is no previous `OP_IF`, this acts as a RETURN.";
    OP_ENDIF => 0x68, "Pop and execute the next statements if a zero element was popped.";
    OP_VERIFY => 0x69, "If the top value is zero or the stack is empty, fail; otherwise, pop the stack.";
    OP_RETURN => 0x6a, "Fail the script immediately. (Must be executed.).";
    OP_TOALTSTACK => 0x6b, "Pop one element from the main stack onto the alt stack.";
    OP_FROMALTSTACK => 0x6c, "Pop one element from the alt stack onto the main stack.";
    OP_2DROP => 0x6d, "Drops the top two stack items.";
    OP_2DUP => 0x6e, "Duplicates the top two stack items as `AB` -> `ABAB`.";
    OP_3DUP => 0x6f, "Duplicates the top three stack items as `ABC` -> `ABCABC`.";
    OP_2OVER => 0x70, "Duplicates the third and fourth items from the top of the stack.";
    OP_2ROT => 0x71, "Moves the two stack items four spaces back to the front, as `xxxxAB` -> `ABxxxx`.";
    OP_2SWAP => 0x72, "Swaps the top two pairs, as `ABCD` -> `CDAB`.";
    OP_IFDUP => 0x73, "Duplicate the top stack element unless it is zero.";
    OP_DEPTH => 0x74, "Push the current number of stack items onto the stack.";
    OP_DROP => 0x75, "Drops the top stack item.";
    OP_DUP => 0x76, "Duplicates the top stack item.";
    OP_NIP => 0x77, "Drops the second-to-top stack item.";
    OP_OVER => 0x78, "Copies the second-to-top stack item, as `xA` -> `AxA`.";
    OP_PICK => 0x79, "Pop the top stack element as N. Copy the Nth stack element to the top.";
    OP_ROLL => 0x7a, "Pop the top stack element as N. Move the Nth stack element to the top.";
    OP_ROT => 0x7b, "Rotate the top three stack items, as `[top next1 next2]` -> `[next2 top next1]`.";
    OP_SWAP => 0x7c, "Swap the top two stack items.";
    OP_TUCK => 0x7d, "Copy the top stack item to before the second item, as `[top next]` -> `[top next top]`.";
    OP_SIZE => 0x82, "Pushes the length of the top stack item onto the stack.";
    OP_EQUAL => 0x87, "Pushes 1 if the inputs are exactly equal, 0 otherwise.";
    OP_EQUALVERIFY => 0x88, "Returns success if the inputs are exactly equal, failure otherwise.";
    OP_1ADD => 0x8b, "Increment the top stack element in place.";
    OP_1SUB => 0x8c, "Decrement the top stack element in place.";
    OP_NEGATE => 0x8f, "Multiply the top stack item by -1 in place.";
    OP_ABS => 0x90, "Absolute value the top stack item in place.";
    OP_NOT => 0x91, "Map 0 to 1 and everything else to 0, in place.";
    OP_0NOTEQUAL => 0x92, "Map 0 to 0 and everything else to 1, in place.";
    OP_ADD => 0x93, "Pop two stack items and push their sum.";
    OP_SUB => 0x94, "Pop two stack items and push the second minus the top.";
    OP_BOOLAND => 0x9a, "Pop the top two stack items and push 1 if both are nonzero, else push 0.";
    OP_BOOLOR => 0x9b, "Pop the top two stack items and push 1 if either is nonzero, else push 0.";
    OP_NUMEQUAL => 0x9c, "Pop the top two stack items and push 1 if both are numerically equal, else push 0.";
    OP_NUMEQUALVERIFY => 0x9d, "Pop the top two stack items and return success if both are numerically equal, else return failure.";
    OP_NUMNOTEQUAL => 0x9e, "Pop the top two stack items and push 0 if both are numerically equal, else push 1.";
    OP_LESSTHAN  => 0x9f, "Pop the top two items; push 1 if the second is less than the top, 0 otherwise.";
    OP_GREATERTHAN  => 0xa0, "Pop the top two items; push 1 if the second is greater than the top, 0 otherwise.";
    OP_LESSTHANOREQUAL  => 0xa1, "Pop the top two items; push 1 if the second is <= the top, 0 otherwise.";
    OP_GREATERTHANOREQUAL  => 0xa2, "Pop the top two items; push 1 if the second is >= the top, 0 otherwise.";
    OP_MIN => 0xa3, "Pop the top two items; push the smaller.";
    OP_MAX => 0xa4, "Pop the top two items; push the larger.";
    OP_WITHIN => 0xa5, "Pop the top three items; if the top is >= the second and < the third, push 1, otherwise push 0.";
    OP_RIPEMD160 => 0xa6, "Pop the top stack item and push its RIPEMD160 hash.";
    OP_SHA1 => 0xa7, "Pop the top stack item and push its SHA1 hash.";
    OP_SHA256 => 0xa8, "Pop the top stack item and push its SHA256 hash.";
    OP_HASH160 => 0xa9, "Pop the top stack item and push its RIPEMD(SHA256) hash.";
    OP_HASH256 => 0xaa, "Pop the top stack item and push its SHA256(SHA256) hash.";
    OP_CODESEPARATOR => 0xab, "Ignore this and everything preceding when deciding what to sign when signature-checking.";
    OP_CHECKSIG => 0xac, "<https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for success/failure.";
    OP_CHECKSIGVERIFY => 0xad, "<https://en.bitcoin.it/wiki/OP_CHECKSIG> returning success/failure.";
    OP_CHECKMULTISIG => 0xae, "Pop N, N pubkeys, M, M signatures, a dummy (due to bug in reference code), \
                      and verify that all M signatures are valid. Push 1 for 'all valid', 0 otherwise.";
    OP_CHECKMULTISIGVERIFY => 0xaf, "Like the above but return success/failure.";
    OP_CHECKSIGADD => 0xba, "`OP_CHECKSIGADD` post tapscript.";
}

/// Read the following byte as a length, and read the following
/// bytes as a push of that length.
#[cfg(feature = "alloc")]
pub(crate) const OP_PUSHDATA1: u8 = 0x4c;

/// Read the following 2 bytes as a little-endian length, and read the following
/// bytes as a push of that length.
#[cfg(feature = "alloc")]
pub(crate) const OP_PUSHDATA2: u8 = 0x4d;

/// Read the following 4 bytes as a little-endian length, and read the following
/// bytes as a push of that length.
#[cfg(feature = "alloc")]
pub(crate) const OP_PUSHDATA4: u8 = 0x4e;

/// Format a byte as a script opcode.
#[cfg(feature = "alloc")]
pub(crate) fn fmt_opcode(op: u8, f: &mut fmt::Formatter) -> fmt::Result {
    match op {
        0x00 => f.write_str("OP_0"),
        0x01..=0x4b => write!(f, "OP_PUSHBYTES_{}", op),
        0x4c => f.write_str("OP_PUSHDATA1"),
        0x4d => f.write_str("OP_PUSHDATA2"),
        0x4e => f.write_str("OP_PUSHDATA4"),
        0x4f => f.write_str("OP_1NEGATE"),
        0x50 => f.write_str("OP_RESERVED"),
        0x51..=0x60 => write!(f, "OP_{}", op - 0x50),
        0x61 => f.write_str("OP_NOP"),
        0x62 => f.write_str("OP_VER"),
        0x63 => f.write_str("OP_IF"),
        0x64 => f.write_str("OP_NOTIF"),
        0x65 => f.write_str("OP_VERIF"),
        0x66 => f.write_str("OP_VERNOTIF"),
        0x67 => f.write_str("OP_ELSE"),
        0x68 => f.write_str("OP_ENDIF"),
        0x69 => f.write_str("OP_VERIFY"),
        0x6a => f.write_str("OP_RETURN"),
        0x6b => f.write_str("OP_TOALTSTACK"),
        0x6c => f.write_str("OP_FROMALTSTACK"),
        0x6d => f.write_str("OP_2DROP"),
        0x6e => f.write_str("OP_2DUP"),
        0x6f => f.write_str("OP_3DUP"),
        0x70 => f.write_str("OP_2OVER"),
        0x71 => f.write_str("OP_2ROT"),
        0x72 => f.write_str("OP_2SWAP"),
        0x73 => f.write_str("OP_IFDUP"),
        0x74 => f.write_str("OP_DEPTH"),
        0x75 => f.write_str("OP_DROP"),
        0x76 => f.write_str("OP_DUP"),
        0x77 => f.write_str("OP_NIP"),
        0x78 => f.write_str("OP_OVER"),
        0x79 => f.write_str("OP_PICK"),
        0x7a => f.write_str("OP_ROLL"),
        0x7b => f.write_str("OP_ROT"),
        0x7c => f.write_str("OP_SWAP"),
        0x7d => f.write_str("OP_TUCK"),
        0x7e => f.write_str("OP_CAT"),
        0x7f => f.write_str("OP_SUBSTR"),
        0x80 => f.write_str("OP_LEFT"),
        0x81 => f.write_str("OP_RIGHT"),
        0x82 => f.write_str("OP_SIZE"),
        0x83 => f.write_str("OP_INVERT"),
        0x84 => f.write_str("OP_AND"),
        0x85 => f.write_str("OP_OR"),
        0x86 => f.write_str("OP_XOR"),
        0x87 => f.write_str("OP_EQUAL"),
        0x88 => f.write_str("OP_EQUALVERIFY"),
        0x89 => f.write_str("OP_RESERVED1"),
        0x8a => f.write_str("OP_RESERVED2"),
        0x8b => f.write_str("OP_1ADD"),
        0x8c => f.write_str("OP_1SUB"),
        0x8d => f.write_str("OP_2MUL"),
        0x8e => f.write_str("OP_2DIV"),
        0x8f => f.write_str("OP_NEGATE"),
        0x90 => f.write_str("OP_ABS"),
        0x91 => f.write_str("OP_NOT"),
        0x92 => f.write_str("OP_0NOTEQUAL"),
        0x93 => f.write_str("OP_ADD"),
        0x94 => f.write_str("OP_SUB"),
        0x95 => f.write_str("OP_MUL"),
        0x96 => f.write_str("OP_DIV"),
        0x97 => f.write_str("OP_MOD"),
        0x98 => f.write_str("OP_LSHIFT"),
        0x99 => f.write_str("OP_RSHIFT"),
        0x9a => f.write_str("OP_BOOLAND"),
        0x9b => f.write_str("OP_BOOLOR"),
        0x9c => f.write_str("OP_NUMEQUAL"),
        0x9d => f.write_str("OP_NUMEQUALVERIFY"),
        0x9e => f.write_str("OP_NUMNOTEQUAL"),
        0x9f => f.write_str("OP_LESSTHAN"),
        0xa0 => f.write_str("OP_GREATERTHAN"),
        0xa1 => f.write_str("OP_LESSTHANOREQUAL"),
        0xa2 => f.write_str("OP_GREATERTHANOREQUAL"),
        0xa3 => f.write_str("OP_MIN"),
        0xa4 => f.write_str("OP_MAX"),
        0xa5 => f.write_str("OP_WITHIN"),
        0xa6 => f.write_str("OP_RIPEMD160"),
        0xa7 => f.write_str("OP_SHA1"),
        0xa8 => f.write_str("OP_SHA256"),
        0xa9 => f.write_str("OP_HASH160"),
        0xaa => f.write_str("OP_HASH256"),
        0xab => f.write_str("OP_CODESEPARATOR"),
        0xac => f.write_str("OP_CHECKSIG"),
        0xad => f.write_str("OP_CHECKSIGVERIFY"),
        0xae => f.write_str("OP_CHECKMULTISIG"),
        0xaf => f.write_str("OP_CHECKMULTISIGVERIFY"),
        0xb1 => f.write_str("OP_CLTV"),
        0xb2 => f.write_str("OP_CSV"),
        0xb0..=0xb9 => write!(f, "OP_NOP{}", op - 0xb0 + 1),
        0xba => f.write_str("OP_CHECKSIGADD"),
        0xbb..=0xfe => write!(f, "OP_RETURN_{}", op),
        0xff => f.write_str("OP_INVALIDOPCODE"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_to_u8_from_u8_roundtrip() {
        for b in 0..=u8::MAX {
            let op = Opcode::from_u8(b);
            assert_eq!(op.to_u8(), b);

            let op = Opcode::from(b);
            assert_eq!(u8::from(op), b);
        }
    }
}
