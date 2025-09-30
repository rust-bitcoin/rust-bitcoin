// SPDX-License-Identifier: CC0-1.0

//! Bitcoin script opcodes.
//!
//! Bitcoin's script uses a stack-based assembly language. This module defines
//! all of the opcodes for that language.

#![allow(non_camel_case_types)]

use core::fmt;

/// Read the following byte as a length, and read the following
/// bytes as a push of that length.
pub const OP_PUSHDATA1: u8 = 0x4c;

/// Read the following 2 bytes as a little-endian length, and read the following
/// bytes as a push of that length.
pub const OP_PUSHDATA2: u8 = 0x4d;

/// Read the following 4 bytes as a little-endian length, and read the following
/// bytes as a push of that length.
pub const OP_PUSHDATA4: u8 = 0x4e;

/// Format a byte as a script opcode.
pub fn fmt_opcode(op: u8, f: &mut fmt::Formatter) -> fmt::Result {
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
