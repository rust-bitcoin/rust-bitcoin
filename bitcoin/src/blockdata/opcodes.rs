// SPDX-License-Identifier: CC0-1.0

//! Bitcoin script opcodes.
//!
//! Bitcoin's script uses a stack-based assembly language. This module defines
//! all of the opcodes for that language.

#![allow(non_camel_case_types)]

use core::fmt;

pub use primitives::opcodes::Opcode;

use self::all::*;

macro_rules! all_opcodes {
    (
        // Opcodes whose constants are defined directly in bitcoin.
        defined { $($op:ident => $val:expr, $doc:expr);* $(;)? }
        // Opcodes re-exported from primitives. Used for opcode_to_str.
        reexported { $($rop:ident),* $(,)? }
    ) => {
        /// Enables wildcard imports to bring into scope all opcodes and nothing else.
        ///
        /// The `all` module is provided so one can use a wildcard import `use bitcoin::opcodes::all::*` to
        /// get all the `OP_FOO` opcodes without getting other types defined in `opcodes` (e.g. `Opcode`, `Class`).
        ///
        /// This module is guaranteed to never contain anything except opcode constants and all opcode
        /// constants are guaranteed to begin with OP_.
        pub mod all {
            use super::Opcode;

            pub use primitives::opcodes::all::*;

            $(
                #[doc = $doc]
                pub const $op: Opcode = Opcode::from_u8($val);
            )*

            /// Helper function for as_str in OpcodeExt.
            pub(super) fn opcode_to_str(opcode: Opcode) -> &'static str {
                match opcode {
                    $(
                        $op => stringify!($op),
                    )*
                    $(
                        $rop => stringify!($rop),
                    )*
                }
            }

            /// Push an empty array onto the stack.
            pub const OP_0: Opcode = OP_PUSHBYTES_0;
            /// Empty stack is also FALSE.
            pub const OP_FALSE: Opcode = OP_PUSHBYTES_0;
            /// Number 1 is also TRUE.
            pub const OP_TRUE: Opcode = OP_1;
            /// Previously called OP_NOP2.
            pub const OP_NOP2: Opcode = OP_CLTV;
            /// Previously called OP_NOP3.
            pub const OP_NOP3: Opcode = OP_CSV;

            /// Push the array `0x81` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_1NEGATE instead")]
            pub const OP_PUSHNUM_NEG1: Opcode = OP_1NEGATE;
            /// Push the array `0x01` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_1 instead")]
            pub const OP_PUSHNUM_1: Opcode = OP_1;
            /// Push the array `0x02` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_2 instead")]
            pub const OP_PUSHNUM_2: Opcode = OP_2;
            /// Push the array `0x03` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_3 instead")]
            pub const OP_PUSHNUM_3: Opcode = OP_3;
            /// Push the array `0x04` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_4 instead")]
            pub const OP_PUSHNUM_4: Opcode = OP_4;
            /// Push the array `0x05` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_5 instead")]
            pub const OP_PUSHNUM_5: Opcode = OP_5;
            /// Push the array `0x06` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_6 instead")]
            pub const OP_PUSHNUM_6: Opcode = OP_6;
            /// Push the array `0x07` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_7 instead")]
            pub const OP_PUSHNUM_7: Opcode = OP_7;
            /// Push the array `0x08` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_8 instead")]
            pub const OP_PUSHNUM_8: Opcode = OP_8;
            /// Push the array `0x09` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_9 instead")]
            pub const OP_PUSHNUM_9: Opcode = OP_9;
            /// Push the array `0x0a` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_10 instead")]
            pub const OP_PUSHNUM_10: Opcode = OP_10;
            /// Push the array `0x0b` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_11 instead")]
            pub const OP_PUSHNUM_11: Opcode = OP_11;
            /// Push the array `0x0c` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_12 instead")]
            pub const OP_PUSHNUM_12: Opcode = OP_12;
            /// Push the array `0x0d` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_13 instead")]
            pub const OP_PUSHNUM_13: Opcode = OP_13;
            /// Push the array `0x0e` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_14 instead")]
            pub const OP_PUSHNUM_14: Opcode = OP_14;
            /// Push the array `0x0f` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_15 instead")]
            pub const OP_PUSHNUM_15: Opcode = OP_15;
            /// Push the array `0x10` onto the stack.
            #[deprecated(since = "TBD", note = "use OP_16 instead")]
            pub const OP_PUSHNUM_16: Opcode = OP_16;
        }
    }
}

all_opcodes! {
    defined {
        OP_PUSHBYTES_0 => 0x00, "Push an empty array onto the stack.";
        OP_PUSHBYTES_1 => 0x01, "Push the next byte as an array onto the stack.";
        OP_PUSHBYTES_2 => 0x02, "Push the next 2 bytes as an array onto the stack.";
        OP_PUSHBYTES_3 => 0x03, "Push the next 3 bytes as an array onto the stack.";
        OP_PUSHBYTES_4 => 0x04, "Push the next 4 bytes as an array onto the stack.";
        OP_PUSHBYTES_5 => 0x05, "Push the next 5 bytes as an array onto the stack.";
        OP_PUSHBYTES_6 => 0x06, "Push the next 6 bytes as an array onto the stack.";
        OP_PUSHBYTES_7 => 0x07, "Push the next 7 bytes as an array onto the stack.";
        OP_PUSHBYTES_8 => 0x08, "Push the next 8 bytes as an array onto the stack.";
        OP_PUSHBYTES_9 => 0x09, "Push the next 9 bytes as an array onto the stack.";
        OP_PUSHBYTES_10 => 0x0a, "Push the next 10 bytes as an array onto the stack.";
        OP_PUSHBYTES_11 => 0x0b, "Push the next 11 bytes as an array onto the stack.";
        OP_PUSHBYTES_12 => 0x0c, "Push the next 12 bytes as an array onto the stack.";
        OP_PUSHBYTES_13 => 0x0d, "Push the next 13 bytes as an array onto the stack.";
        OP_PUSHBYTES_14 => 0x0e, "Push the next 14 bytes as an array onto the stack.";
        OP_PUSHBYTES_15 => 0x0f, "Push the next 15 bytes as an array onto the stack.";
        OP_PUSHBYTES_16 => 0x10, "Push the next 16 bytes as an array onto the stack.";
        OP_PUSHBYTES_17 => 0x11, "Push the next 17 bytes as an array onto the stack.";
        OP_PUSHBYTES_18 => 0x12, "Push the next 18 bytes as an array onto the stack.";
        OP_PUSHBYTES_19 => 0x13, "Push the next 19 bytes as an array onto the stack.";
        OP_PUSHBYTES_20 => 0x14, "Push the next 20 bytes as an array onto the stack.";
        OP_PUSHBYTES_21 => 0x15, "Push the next 21 bytes as an array onto the stack.";
        OP_PUSHBYTES_22 => 0x16, "Push the next 22 bytes as an array onto the stack.";
        OP_PUSHBYTES_23 => 0x17, "Push the next 23 bytes as an array onto the stack.";
        OP_PUSHBYTES_24 => 0x18, "Push the next 24 bytes as an array onto the stack.";
        OP_PUSHBYTES_25 => 0x19, "Push the next 25 bytes as an array onto the stack.";
        OP_PUSHBYTES_26 => 0x1a, "Push the next 26 bytes as an array onto the stack.";
        OP_PUSHBYTES_27 => 0x1b, "Push the next 27 bytes as an array onto the stack.";
        OP_PUSHBYTES_28 => 0x1c, "Push the next 28 bytes as an array onto the stack.";
        OP_PUSHBYTES_29 => 0x1d, "Push the next 29 bytes as an array onto the stack.";
        OP_PUSHBYTES_30 => 0x1e, "Push the next 30 bytes as an array onto the stack.";
        OP_PUSHBYTES_31 => 0x1f, "Push the next 31 bytes as an array onto the stack.";
        OP_PUSHBYTES_32 => 0x20, "Push the next 32 bytes as an array onto the stack.";
        OP_PUSHBYTES_33 => 0x21, "Push the next 33 bytes as an array onto the stack.";
        OP_PUSHBYTES_34 => 0x22, "Push the next 34 bytes as an array onto the stack.";
        OP_PUSHBYTES_35 => 0x23, "Push the next 35 bytes as an array onto the stack.";
        OP_PUSHBYTES_36 => 0x24, "Push the next 36 bytes as an array onto the stack.";
        OP_PUSHBYTES_37 => 0x25, "Push the next 37 bytes as an array onto the stack.";
        OP_PUSHBYTES_38 => 0x26, "Push the next 38 bytes as an array onto the stack.";
        OP_PUSHBYTES_39 => 0x27, "Push the next 39 bytes as an array onto the stack.";
        OP_PUSHBYTES_40 => 0x28, "Push the next 40 bytes as an array onto the stack.";
        OP_PUSHBYTES_41 => 0x29, "Push the next 41 bytes as an array onto the stack.";
        OP_PUSHBYTES_42 => 0x2a, "Push the next 42 bytes as an array onto the stack.";
        OP_PUSHBYTES_43 => 0x2b, "Push the next 43 bytes as an array onto the stack.";
        OP_PUSHBYTES_44 => 0x2c, "Push the next 44 bytes as an array onto the stack.";
        OP_PUSHBYTES_45 => 0x2d, "Push the next 45 bytes as an array onto the stack.";
        OP_PUSHBYTES_46 => 0x2e, "Push the next 46 bytes as an array onto the stack.";
        OP_PUSHBYTES_47 => 0x2f, "Push the next 47 bytes as an array onto the stack.";
        OP_PUSHBYTES_48 => 0x30, "Push the next 48 bytes as an array onto the stack.";
        OP_PUSHBYTES_49 => 0x31, "Push the next 49 bytes as an array onto the stack.";
        OP_PUSHBYTES_50 => 0x32, "Push the next 50 bytes as an array onto the stack.";
        OP_PUSHBYTES_51 => 0x33, "Push the next 51 bytes as an array onto the stack.";
        OP_PUSHBYTES_52 => 0x34, "Push the next 52 bytes as an array onto the stack.";
        OP_PUSHBYTES_53 => 0x35, "Push the next 53 bytes as an array onto the stack.";
        OP_PUSHBYTES_54 => 0x36, "Push the next 54 bytes as an array onto the stack.";
        OP_PUSHBYTES_55 => 0x37, "Push the next 55 bytes as an array onto the stack.";
        OP_PUSHBYTES_56 => 0x38, "Push the next 56 bytes as an array onto the stack.";
        OP_PUSHBYTES_57 => 0x39, "Push the next 57 bytes as an array onto the stack.";
        OP_PUSHBYTES_58 => 0x3a, "Push the next 58 bytes as an array onto the stack.";
        OP_PUSHBYTES_59 => 0x3b, "Push the next 59 bytes as an array onto the stack.";
        OP_PUSHBYTES_60 => 0x3c, "Push the next 60 bytes as an array onto the stack.";
        OP_PUSHBYTES_61 => 0x3d, "Push the next 61 bytes as an array onto the stack.";
        OP_PUSHBYTES_62 => 0x3e, "Push the next 62 bytes as an array onto the stack.";
        OP_PUSHBYTES_63 => 0x3f, "Push the next 63 bytes as an array onto the stack.";
        OP_PUSHBYTES_64 => 0x40, "Push the next 64 bytes as an array onto the stack.";
        OP_PUSHBYTES_65 => 0x41, "Push the next 65 bytes as an array onto the stack.";
        OP_PUSHBYTES_66 => 0x42, "Push the next 66 bytes as an array onto the stack.";
        OP_PUSHBYTES_67 => 0x43, "Push the next 67 bytes as an array onto the stack.";
        OP_PUSHBYTES_68 => 0x44, "Push the next 68 bytes as an array onto the stack.";
        OP_PUSHBYTES_69 => 0x45, "Push the next 69 bytes as an array onto the stack.";
        OP_PUSHBYTES_70 => 0x46, "Push the next 70 bytes as an array onto the stack.";
        OP_PUSHBYTES_71 => 0x47, "Push the next 71 bytes as an array onto the stack.";
        OP_PUSHBYTES_72 => 0x48, "Push the next 72 bytes as an array onto the stack.";
        OP_PUSHBYTES_73 => 0x49, "Push the next 73 bytes as an array onto the stack.";
        OP_PUSHBYTES_74 => 0x4a, "Push the next 74 bytes as an array onto the stack.";
        OP_PUSHBYTES_75 => 0x4b, "Push the next 75 bytes as an array onto the stack.";
        OP_PUSHDATA1 => 0x4c, "Read the next byte as N; push the next N bytes as an array onto the stack.";
        OP_PUSHDATA2 => 0x4d, "Read the next 2 bytes as N; push the next N bytes as an array onto the stack.";
        OP_PUSHDATA4 => 0x4e, "Read the next 4 bytes as N; push the next N bytes as an array onto the stack.";
        OP_RESERVED => 0x50, "Synonym for `OP_RETURN`.";
        OP_VER => 0x62, "Synonym for `OP_RETURN`.";
        OP_VERIF => 0x65, "Fail the script unconditionally, does not even need to be executed.";
        OP_VERNOTIF => 0x66, "Fail the script unconditionally, does not even need to be executed.";
        OP_CAT => 0x7e, "Fail the script unconditionally, does not even need to be executed.";
        OP_SUBSTR => 0x7f, "Fail the script unconditionally, does not even need to be executed.";
        OP_LEFT => 0x80, "Fail the script unconditionally, does not even need to be executed.";
        OP_RIGHT => 0x81, "Fail the script unconditionally, does not even need to be executed.";
        OP_INVERT => 0x83, "Fail the script unconditionally, does not even need to be executed.";
        OP_AND => 0x84, "Fail the script unconditionally, does not even need to be executed.";
        OP_OR => 0x85, "Fail the script unconditionally, does not even need to be executed.";
        OP_XOR => 0x86, "Fail the script unconditionally, does not even need to be executed.";
        OP_RESERVED1 => 0x89, "Synonym for `OP_RETURN`.";
        OP_RESERVED2 => 0x8a, "Synonym for `OP_RETURN`.";
        OP_2MUL => 0x8d, "Fail the script unconditionally, does not even need to be executed.";
        OP_2DIV => 0x8e, "Fail the script unconditionally, does not even need to be executed.";
        OP_MUL => 0x95, "Fail the script unconditionally, does not even need to be executed.";
        OP_DIV => 0x96, "Fail the script unconditionally, does not even need to be executed.";
        OP_MOD => 0x97, "Fail the script unconditionally, does not even need to be executed.";
        OP_LSHIFT => 0x98, "Fail the script unconditionally, does not even need to be executed.";
        OP_RSHIFT => 0x99, "Fail the script unconditionally, does not even need to be executed.";
        OP_NOP1 => 0xb0, "Does nothing.";
        OP_CLTV => 0xb1, "<https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>";
        OP_CSV => 0xb2, "<https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki>";
        OP_NOP4 => 0xb3, "Does nothing.";
        OP_NOP5 => 0xb4, "Does nothing.";
        OP_NOP6 => 0xb5, "Does nothing.";
        OP_NOP7 => 0xb6, "Does nothing.";
        OP_NOP8 => 0xb7, "Does nothing.";
        OP_NOP9 => 0xb8, "Does nothing.";
        OP_NOP10 => 0xb9, "Does nothing.";
        // Every other opcode acts as OP_RETURN
        OP_RETURN_187 => 0xbb, "Synonym for `OP_RETURN`.";
        OP_RETURN_188 => 0xbc, "Synonym for `OP_RETURN`.";
        OP_RETURN_189 => 0xbd, "Synonym for `OP_RETURN`.";
        OP_RETURN_190 => 0xbe, "Synonym for `OP_RETURN`.";
        OP_RETURN_191 => 0xbf, "Synonym for `OP_RETURN`.";
        OP_RETURN_192 => 0xc0, "Synonym for `OP_RETURN`.";
        OP_RETURN_193 => 0xc1, "Synonym for `OP_RETURN`.";
        OP_RETURN_194 => 0xc2, "Synonym for `OP_RETURN`.";
        OP_RETURN_195 => 0xc3, "Synonym for `OP_RETURN`.";
        OP_RETURN_196 => 0xc4, "Synonym for `OP_RETURN`.";
        OP_RETURN_197 => 0xc5, "Synonym for `OP_RETURN`.";
        OP_RETURN_198 => 0xc6, "Synonym for `OP_RETURN`.";
        OP_RETURN_199 => 0xc7, "Synonym for `OP_RETURN`.";
        OP_RETURN_200 => 0xc8, "Synonym for `OP_RETURN`.";
        OP_RETURN_201 => 0xc9, "Synonym for `OP_RETURN`.";
        OP_RETURN_202 => 0xca, "Synonym for `OP_RETURN`.";
        OP_RETURN_203 => 0xcb, "Synonym for `OP_RETURN`.";
        OP_RETURN_204 => 0xcc, "Synonym for `OP_RETURN`.";
        OP_RETURN_205 => 0xcd, "Synonym for `OP_RETURN`.";
        OP_RETURN_206 => 0xce, "Synonym for `OP_RETURN`.";
        OP_RETURN_207 => 0xcf, "Synonym for `OP_RETURN`.";
        OP_RETURN_208 => 0xd0, "Synonym for `OP_RETURN`.";
        OP_RETURN_209 => 0xd1, "Synonym for `OP_RETURN`.";
        OP_RETURN_210 => 0xd2, "Synonym for `OP_RETURN`.";
        OP_RETURN_211 => 0xd3, "Synonym for `OP_RETURN`.";
        OP_RETURN_212 => 0xd4, "Synonym for `OP_RETURN`.";
        OP_RETURN_213 => 0xd5, "Synonym for `OP_RETURN`.";
        OP_RETURN_214 => 0xd6, "Synonym for `OP_RETURN`.";
        OP_RETURN_215 => 0xd7, "Synonym for `OP_RETURN`.";
        OP_RETURN_216 => 0xd8, "Synonym for `OP_RETURN`.";
        OP_RETURN_217 => 0xd9, "Synonym for `OP_RETURN`.";
        OP_RETURN_218 => 0xda, "Synonym for `OP_RETURN`.";
        OP_RETURN_219 => 0xdb, "Synonym for `OP_RETURN`.";
        OP_RETURN_220 => 0xdc, "Synonym for `OP_RETURN`.";
        OP_RETURN_221 => 0xdd, "Synonym for `OP_RETURN`.";
        OP_RETURN_222 => 0xde, "Synonym for `OP_RETURN`.";
        OP_RETURN_223 => 0xdf, "Synonym for `OP_RETURN`.";
        OP_RETURN_224 => 0xe0, "Synonym for `OP_RETURN`.";
        OP_RETURN_225 => 0xe1, "Synonym for `OP_RETURN`.";
        OP_RETURN_226 => 0xe2, "Synonym for `OP_RETURN`.";
        OP_RETURN_227 => 0xe3, "Synonym for `OP_RETURN`.";
        OP_RETURN_228 => 0xe4, "Synonym for `OP_RETURN`.";
        OP_RETURN_229 => 0xe5, "Synonym for `OP_RETURN`.";
        OP_RETURN_230 => 0xe6, "Synonym for `OP_RETURN`.";
        OP_RETURN_231 => 0xe7, "Synonym for `OP_RETURN`.";
        OP_RETURN_232 => 0xe8, "Synonym for `OP_RETURN`.";
        OP_RETURN_233 => 0xe9, "Synonym for `OP_RETURN`.";
        OP_RETURN_234 => 0xea, "Synonym for `OP_RETURN`.";
        OP_RETURN_235 => 0xeb, "Synonym for `OP_RETURN`.";
        OP_RETURN_236 => 0xec, "Synonym for `OP_RETURN`.";
        OP_RETURN_237 => 0xed, "Synonym for `OP_RETURN`.";
        OP_RETURN_238 => 0xee, "Synonym for `OP_RETURN`.";
        OP_RETURN_239 => 0xef, "Synonym for `OP_RETURN`.";
        OP_RETURN_240 => 0xf0, "Synonym for `OP_RETURN`.";
        OP_RETURN_241 => 0xf1, "Synonym for `OP_RETURN`.";
        OP_RETURN_242 => 0xf2, "Synonym for `OP_RETURN`.";
        OP_RETURN_243 => 0xf3, "Synonym for `OP_RETURN`.";
        OP_RETURN_244 => 0xf4, "Synonym for `OP_RETURN`.";
        OP_RETURN_245 => 0xf5, "Synonym for `OP_RETURN`.";
        OP_RETURN_246 => 0xf6, "Synonym for `OP_RETURN`.";
        OP_RETURN_247 => 0xf7, "Synonym for `OP_RETURN`.";
        OP_RETURN_248 => 0xf8, "Synonym for `OP_RETURN`.";
        OP_RETURN_249 => 0xf9, "Synonym for `OP_RETURN`.";
        OP_RETURN_250 => 0xfa, "Synonym for `OP_RETURN`.";
        OP_RETURN_251 => 0xfb, "Synonym for `OP_RETURN`.";
        OP_RETURN_252 => 0xfc, "Synonym for `OP_RETURN`.";
        OP_RETURN_253 => 0xfd, "Synonym for `OP_RETURN`.";
        OP_RETURN_254 => 0xfe, "Synonym for `OP_RETURN`.";
        OP_INVALIDOPCODE => 0xff, "Synonym for `OP_RETURN`."
    }
    reexported {
        OP_1NEGATE,
        OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
        OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,
        OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN, OP_TOALTSTACK, OP_FROMALTSTACK,
        OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_IFDUP, OP_DEPTH,
        OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP,
        OP_TUCK, OP_SIZE, OP_EQUAL, OP_EQUALVERIFY, OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS,
        OP_NOT, OP_0NOTEQUAL, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
        OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN,
        OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256, OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY,
        OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIGADD,
    }
}

/// Classification context for the opcode.
///
/// Some opcodes like [`OP_RESERVED`] abort the script in `ClassifyContext::Legacy` context,
/// but will act as `OP_SUCCESSx` in `ClassifyContext::TapScript` (see BIP-0342 for full list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassifyContext {
    /// Opcode used in tapscript context.
    TapScript,
    /// Opcode used in legacy context.
    Legacy,
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Opcode {}
}

crate::internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Opcode`] type.
    pub trait OpcodeExt impl for Opcode {
        /// Classifies an Opcode into a broad class.
        #[inline]
        #[must_use]
        fn classify(self, ctx: ClassifyContext) -> Class {
            match (self, ctx) {
                // 3 opcodes illegal in all contexts
                (OP_VERIF, _) | (OP_VERNOTIF, _) | (OP_INVALIDOPCODE, _) => Class::IllegalOp,

                // 15 opcodes illegal in Legacy context
                #[rustfmt::skip]
                (OP_CAT, ctx) | (OP_SUBSTR, ctx)
                | (OP_LEFT, ctx) | (OP_RIGHT, ctx)
                | (OP_INVERT, ctx)
                | (OP_AND, ctx) | (OP_OR, ctx) | (OP_XOR, ctx)
                | (OP_2MUL, ctx) | (OP_2DIV, ctx)
                | (OP_MUL, ctx) | (OP_DIV, ctx) | (OP_MOD, ctx)
                | (OP_LSHIFT, ctx) | (OP_RSHIFT, ctx) if ctx == ClassifyContext::Legacy => Class::IllegalOp,

                // 87 opcodes of SuccessOp class only in TapScript context
                (op, ClassifyContext::TapScript)
                    if op.to_u8() == 80
                        || op.to_u8() == 98
                        || (op.to_u8() >= 126 && op.to_u8() <= 129)
                        || (op.to_u8() >= 131 && op.to_u8() <= 134)
                        || (op.to_u8() >= 137 && op.to_u8() <= 138)
                        || (op.to_u8() >= 141 && op.to_u8() <= 142)
                        || (op.to_u8() >= 149 && op.to_u8() <= 153)
                        || (op.to_u8() >= 187 && op.to_u8() <= 254) =>
                    Class::SuccessOp,

                // 11 opcodes of NoOp class
                (OP_NOP, _) => Class::NoOp,
                (op, _) if op.to_u8() >= OP_NOP1.to_u8() && op.to_u8() <= OP_NOP10.to_u8() => Class::NoOp,

                // 1 opcode for `OP_RETURN`
                (OP_RETURN, _) => Class::ReturnOp,

                // 4 opcodes operating equally to `OP_RETURN` only in Legacy context
                (OP_RESERVED, ctx) | (OP_RESERVED1, ctx) | (OP_RESERVED2, ctx) | (OP_VER, ctx)
                    if ctx == ClassifyContext::Legacy =>
                    Class::ReturnOp,

                // 71 opcodes operating equally to `OP_RETURN` only in Legacy context
                (op, ClassifyContext::Legacy) if op.to_u8() >= OP_CHECKSIGADD.to_u8() => Class::ReturnOp,

                // 2 opcodes operating equally to `OP_RETURN` only in TapScript context
                (OP_CHECKMULTISIG, ClassifyContext::TapScript)
                | (OP_CHECKMULTISIGVERIFY, ClassifyContext::TapScript) => Class::ReturnOp,

                // 1 opcode of PushNum class
                (OP_1NEGATE, _) => Class::PushNum(-1),

                // 16 opcodes of PushNum class
                (op, _) if op.to_u8() >= OP_1.to_u8() && op.to_u8() <= OP_16.to_u8() =>
                    Class::PushNum(1 + self.to_u8() as i32 - OP_1.to_u8() as i32),

                // 76 opcodes of PushBytes class
                (op, _) if op.to_u8() <= OP_PUSHBYTES_75.to_u8() => Class::PushBytes(self.to_u8() as u32),

                // opcodes of Ordinary class: 61 for Legacy and 60 for TapScript context
                (_, _) => Class::Ordinary(Ordinary::with(self)),
            }
        }

        /// Decodes PUSHNUM [`Opcode`] as a `u8` representing its number (1-16).
        ///
        /// Does not convert `OP_FALSE` to 0. Only `1` to `OP_PUSHNUM_16` are covered.
        ///
        /// # Returns
        ///
        /// Returns `None` if `self` is not a PUSHNUM.
        #[inline]
        #[must_use]
        fn decode_pushnum(self) -> Option<u8> {
            const START: u8 = OP_1.to_u8();
            const END: u8 = OP_16.to_u8();
            match self.to_u8() {
                START..=END => Some(self.to_u8() - START + 1),
                _ => None,
            }
        }

        /// Returns the string representation of the opcode.
        ///
        /// This function maps the `Opcode`'s `code` value (a `u8`) to its corresponding
        /// Bitcoin Script opcode name.
        ///
        /// # Example
        /// ```
        /// use bitcoin::opcodes::all::*;
        /// use bitcoin::opcodes::OpcodeExt as _;
        ///
        /// assert_eq!(OP_1.as_str(), "OP_1");
        /// assert_eq!(OP_1NEGATE.as_str(), "OP_1NEGATE");
        /// assert_eq!(OP_CHECKMULTISIG.as_str(), "OP_CHECKMULTISIG");
        /// ```
        #[inline]
        fn as_str(&self) -> &'static str { all::opcode_to_str(*self) }
    }
}

/// Broad categories of opcodes with similar behavior.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Class {
    /// Pushes the given number onto the stack.
    PushNum(i32),
    /// Pushes the given number of bytes onto the stack.
    PushBytes(u32),
    /// Fails the script if executed.
    ReturnOp,
    /// Succeeds the script even if not executed.
    SuccessOp,
    /// Fails the script even if not executed.
    IllegalOp,
    /// Does nothing.
    NoOp,
    /// Any opcode not covered above.
    Ordinary(Ordinary),
}

macro_rules! ordinary_opcode {
    ($($op:ident),*) => (
        #[repr(u8)]
        #[doc(hidden)]
        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        pub enum Ordinary {
            $( $op = $op.to_u8() ),*
        }

        impl fmt::Display for Ordinary {
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                match *self {
                   $(Ordinary::$op => { f.pad(stringify!($op)) }),*
                }
            }
        }

        impl Ordinary {
            fn with(b: Opcode) -> Self {
                match b {
                    $( $op => { Ordinary::$op } ),*
                    _ => unreachable!("construction of `Ordinary` type from non-ordinary opcode {}", b.as_str()),
                }
            }

            /// Constructs a new [`Ordinary`] from an [`Opcode`].
            pub fn from_opcode(b: Opcode) -> Option<Self> {
                match b {
                    $( $op => { Some(Ordinary::$op) } ),*
                    _ => None,
                }
            }
        }
    );
}

// "Ordinary" opcodes -- should be 61 of these
ordinary_opcode! {
    // pushdata
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    // control flow
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY,
    // stack
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,
    OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK,
    OP_IFDUP, OP_DEPTH, OP_SIZE,
    // equality
    OP_EQUAL, OP_EQUALVERIFY,
    // arithmetic
    OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL,
    OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR,
    OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN,
    OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL,
    OP_MIN, OP_MAX, OP_WITHIN,
    // crypto
    OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,
    OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIGADD
}

impl Ordinary {
    /// Encodes [`Opcode`] as a byte.
    #[inline]
    pub fn to_u8(self) -> u8 { self as u8 }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::collections::HashSet;

    use super::*;

    #[cfg(feature = "std")]
    macro_rules! roundtrip {
        ($unique:expr, $op:ident) => {
            assert_eq!($op, Opcode::from($op.to_u8()));

            let s1 = format!("{}", $op.as_str());
            assert_eq!(s1, stringify!($op));
            assert!($unique.insert(s1));
        };
    }

    #[test]
    fn formatting_works() {
        let op = all::OP_NOP;
        let s = format!("{:>10}", op.as_str());
        assert_eq!(s, "    OP_NOP");
    }

    #[test]
    fn ordinary_op_code() {
        let ordinary_op = Ordinary::from_opcode(OP_PUSHDATA1).expect("0x4C");
        assert_eq!(ordinary_op.to_u8(), 0x4C_u8);
    }

    #[test]
    fn decode_pushnum() {
        // Test all possible opcodes
        // - Sanity check
        assert_eq!(OP_1.to_u8(), 0x51_u8);
        assert_eq!(OP_16.to_u8(), 0x60_u8);
        for i in 0x00..=0xff_u8 {
            let expected = match i {
                // OP_1 ..= OP_16
                0x51..=0x60 => Some(i - 0x50),
                _ => None,
            };
            assert_eq!(Opcode::from(i).decode_pushnum(), expected);
        }

        // Test the named opcode constants
        // - This is the OP right before PUSHNUMs start
        assert!(OP_RESERVED.decode_pushnum().is_none());
        assert_eq!(OP_1.decode_pushnum().expect("pushnum"), 1);
        assert_eq!(OP_2.decode_pushnum().expect("pushnum"), 2);
        assert_eq!(OP_3.decode_pushnum().expect("pushnum"), 3);
        assert_eq!(OP_4.decode_pushnum().expect("pushnum"), 4);
        assert_eq!(OP_5.decode_pushnum().expect("pushnum"), 5);
        assert_eq!(OP_6.decode_pushnum().expect("pushnum"), 6);
        assert_eq!(OP_7.decode_pushnum().expect("pushnum"), 7);
        assert_eq!(OP_8.decode_pushnum().expect("pushnum"), 8);
        assert_eq!(OP_9.decode_pushnum().expect("pushnum"), 9);
        assert_eq!(OP_10.decode_pushnum().expect("pushnum"), 10);
        assert_eq!(OP_11.decode_pushnum().expect("pushnum"), 11);
        assert_eq!(OP_12.decode_pushnum().expect("pushnum"), 12);
        assert_eq!(OP_13.decode_pushnum().expect("pushnum"), 13);
        assert_eq!(OP_14.decode_pushnum().expect("pushnum"), 14);
        assert_eq!(OP_15.decode_pushnum().expect("pushnum"), 15);
        assert_eq!(OP_16.decode_pushnum().expect("pushnum"), 16);
        // - This is the OP right after PUSHNUMs end
        assert!(OP_NOP.decode_pushnum().is_none());
    }

    #[test]
    fn classify_test() {
        let op174 = OP_CHECKMULTISIG;
        assert_eq!(
            op174.classify(ClassifyContext::Legacy),
            Class::Ordinary(Ordinary::OP_CHECKMULTISIG)
        );
        assert_eq!(op174.classify(ClassifyContext::TapScript), Class::ReturnOp);

        let op175 = OP_CHECKMULTISIGVERIFY;
        assert_eq!(
            op175.classify(ClassifyContext::Legacy),
            Class::Ordinary(Ordinary::OP_CHECKMULTISIGVERIFY)
        );
        assert_eq!(op175.classify(ClassifyContext::TapScript), Class::ReturnOp);

        let op186 = OP_CHECKSIGADD;
        assert_eq!(op186.classify(ClassifyContext::Legacy), Class::ReturnOp);
        assert_eq!(
            op186.classify(ClassifyContext::TapScript),
            Class::Ordinary(Ordinary::OP_CHECKSIGADD)
        );

        let op187 = OP_RETURN_187;
        assert_eq!(op187.classify(ClassifyContext::Legacy), Class::ReturnOp);
        assert_eq!(op187.classify(ClassifyContext::TapScript), Class::SuccessOp);
    }

    #[test]
    #[cfg(feature = "std")]
    fn str_roundtrip() {
        let mut unique = HashSet::new();
        roundtrip!(unique, OP_PUSHBYTES_0);
        roundtrip!(unique, OP_PUSHBYTES_1);
        roundtrip!(unique, OP_PUSHBYTES_2);
        roundtrip!(unique, OP_PUSHBYTES_3);
        roundtrip!(unique, OP_PUSHBYTES_4);
        roundtrip!(unique, OP_PUSHBYTES_5);
        roundtrip!(unique, OP_PUSHBYTES_6);
        roundtrip!(unique, OP_PUSHBYTES_7);
        roundtrip!(unique, OP_PUSHBYTES_8);
        roundtrip!(unique, OP_PUSHBYTES_9);
        roundtrip!(unique, OP_PUSHBYTES_10);
        roundtrip!(unique, OP_PUSHBYTES_11);
        roundtrip!(unique, OP_PUSHBYTES_12);
        roundtrip!(unique, OP_PUSHBYTES_13);
        roundtrip!(unique, OP_PUSHBYTES_14);
        roundtrip!(unique, OP_PUSHBYTES_15);
        roundtrip!(unique, OP_PUSHBYTES_16);
        roundtrip!(unique, OP_PUSHBYTES_17);
        roundtrip!(unique, OP_PUSHBYTES_18);
        roundtrip!(unique, OP_PUSHBYTES_19);
        roundtrip!(unique, OP_PUSHBYTES_20);
        roundtrip!(unique, OP_PUSHBYTES_21);
        roundtrip!(unique, OP_PUSHBYTES_22);
        roundtrip!(unique, OP_PUSHBYTES_23);
        roundtrip!(unique, OP_PUSHBYTES_24);
        roundtrip!(unique, OP_PUSHBYTES_25);
        roundtrip!(unique, OP_PUSHBYTES_26);
        roundtrip!(unique, OP_PUSHBYTES_27);
        roundtrip!(unique, OP_PUSHBYTES_28);
        roundtrip!(unique, OP_PUSHBYTES_29);
        roundtrip!(unique, OP_PUSHBYTES_30);
        roundtrip!(unique, OP_PUSHBYTES_31);
        roundtrip!(unique, OP_PUSHBYTES_32);
        roundtrip!(unique, OP_PUSHBYTES_33);
        roundtrip!(unique, OP_PUSHBYTES_34);
        roundtrip!(unique, OP_PUSHBYTES_35);
        roundtrip!(unique, OP_PUSHBYTES_36);
        roundtrip!(unique, OP_PUSHBYTES_37);
        roundtrip!(unique, OP_PUSHBYTES_38);
        roundtrip!(unique, OP_PUSHBYTES_39);
        roundtrip!(unique, OP_PUSHBYTES_40);
        roundtrip!(unique, OP_PUSHBYTES_41);
        roundtrip!(unique, OP_PUSHBYTES_42);
        roundtrip!(unique, OP_PUSHBYTES_43);
        roundtrip!(unique, OP_PUSHBYTES_44);
        roundtrip!(unique, OP_PUSHBYTES_45);
        roundtrip!(unique, OP_PUSHBYTES_46);
        roundtrip!(unique, OP_PUSHBYTES_47);
        roundtrip!(unique, OP_PUSHBYTES_48);
        roundtrip!(unique, OP_PUSHBYTES_49);
        roundtrip!(unique, OP_PUSHBYTES_50);
        roundtrip!(unique, OP_PUSHBYTES_51);
        roundtrip!(unique, OP_PUSHBYTES_52);
        roundtrip!(unique, OP_PUSHBYTES_53);
        roundtrip!(unique, OP_PUSHBYTES_54);
        roundtrip!(unique, OP_PUSHBYTES_55);
        roundtrip!(unique, OP_PUSHBYTES_56);
        roundtrip!(unique, OP_PUSHBYTES_57);
        roundtrip!(unique, OP_PUSHBYTES_58);
        roundtrip!(unique, OP_PUSHBYTES_59);
        roundtrip!(unique, OP_PUSHBYTES_60);
        roundtrip!(unique, OP_PUSHBYTES_61);
        roundtrip!(unique, OP_PUSHBYTES_62);
        roundtrip!(unique, OP_PUSHBYTES_63);
        roundtrip!(unique, OP_PUSHBYTES_64);
        roundtrip!(unique, OP_PUSHBYTES_65);
        roundtrip!(unique, OP_PUSHBYTES_66);
        roundtrip!(unique, OP_PUSHBYTES_67);
        roundtrip!(unique, OP_PUSHBYTES_68);
        roundtrip!(unique, OP_PUSHBYTES_69);
        roundtrip!(unique, OP_PUSHBYTES_70);
        roundtrip!(unique, OP_PUSHBYTES_71);
        roundtrip!(unique, OP_PUSHBYTES_72);
        roundtrip!(unique, OP_PUSHBYTES_73);
        roundtrip!(unique, OP_PUSHBYTES_74);
        roundtrip!(unique, OP_PUSHBYTES_75);
        roundtrip!(unique, OP_PUSHDATA1);
        roundtrip!(unique, OP_PUSHDATA2);
        roundtrip!(unique, OP_PUSHDATA4);
        roundtrip!(unique, OP_1NEGATE);
        roundtrip!(unique, OP_RESERVED);
        roundtrip!(unique, OP_1);
        roundtrip!(unique, OP_2);
        roundtrip!(unique, OP_3);
        roundtrip!(unique, OP_4);
        roundtrip!(unique, OP_5);
        roundtrip!(unique, OP_6);
        roundtrip!(unique, OP_7);
        roundtrip!(unique, OP_8);
        roundtrip!(unique, OP_9);
        roundtrip!(unique, OP_10);
        roundtrip!(unique, OP_11);
        roundtrip!(unique, OP_12);
        roundtrip!(unique, OP_13);
        roundtrip!(unique, OP_14);
        roundtrip!(unique, OP_15);
        roundtrip!(unique, OP_16);
        roundtrip!(unique, OP_NOP);
        roundtrip!(unique, OP_VER);
        roundtrip!(unique, OP_IF);
        roundtrip!(unique, OP_NOTIF);
        roundtrip!(unique, OP_VERIF);
        roundtrip!(unique, OP_VERNOTIF);
        roundtrip!(unique, OP_ELSE);
        roundtrip!(unique, OP_ENDIF);
        roundtrip!(unique, OP_VERIFY);
        roundtrip!(unique, OP_RETURN);
        roundtrip!(unique, OP_TOALTSTACK);
        roundtrip!(unique, OP_FROMALTSTACK);
        roundtrip!(unique, OP_2DROP);
        roundtrip!(unique, OP_2DUP);
        roundtrip!(unique, OP_3DUP);
        roundtrip!(unique, OP_2OVER);
        roundtrip!(unique, OP_2ROT);
        roundtrip!(unique, OP_2SWAP);
        roundtrip!(unique, OP_IFDUP);
        roundtrip!(unique, OP_DEPTH);
        roundtrip!(unique, OP_DROP);
        roundtrip!(unique, OP_DUP);
        roundtrip!(unique, OP_NIP);
        roundtrip!(unique, OP_OVER);
        roundtrip!(unique, OP_PICK);
        roundtrip!(unique, OP_ROLL);
        roundtrip!(unique, OP_ROT);
        roundtrip!(unique, OP_SWAP);
        roundtrip!(unique, OP_TUCK);
        roundtrip!(unique, OP_CAT);
        roundtrip!(unique, OP_SUBSTR);
        roundtrip!(unique, OP_LEFT);
        roundtrip!(unique, OP_RIGHT);
        roundtrip!(unique, OP_SIZE);
        roundtrip!(unique, OP_INVERT);
        roundtrip!(unique, OP_AND);
        roundtrip!(unique, OP_OR);
        roundtrip!(unique, OP_XOR);
        roundtrip!(unique, OP_EQUAL);
        roundtrip!(unique, OP_EQUALVERIFY);
        roundtrip!(unique, OP_RESERVED1);
        roundtrip!(unique, OP_RESERVED2);
        roundtrip!(unique, OP_1ADD);
        roundtrip!(unique, OP_1SUB);
        roundtrip!(unique, OP_2MUL);
        roundtrip!(unique, OP_2DIV);
        roundtrip!(unique, OP_NEGATE);
        roundtrip!(unique, OP_ABS);
        roundtrip!(unique, OP_NOT);
        roundtrip!(unique, OP_0NOTEQUAL);
        roundtrip!(unique, OP_ADD);
        roundtrip!(unique, OP_SUB);
        roundtrip!(unique, OP_MUL);
        roundtrip!(unique, OP_DIV);
        roundtrip!(unique, OP_MOD);
        roundtrip!(unique, OP_LSHIFT);
        roundtrip!(unique, OP_RSHIFT);
        roundtrip!(unique, OP_BOOLAND);
        roundtrip!(unique, OP_BOOLOR);
        roundtrip!(unique, OP_NUMEQUAL);
        roundtrip!(unique, OP_NUMEQUALVERIFY);
        roundtrip!(unique, OP_NUMNOTEQUAL);
        roundtrip!(unique, OP_LESSTHAN);
        roundtrip!(unique, OP_GREATERTHAN);
        roundtrip!(unique, OP_LESSTHANOREQUAL);
        roundtrip!(unique, OP_GREATERTHANOREQUAL);
        roundtrip!(unique, OP_MIN);
        roundtrip!(unique, OP_MAX);
        roundtrip!(unique, OP_WITHIN);
        roundtrip!(unique, OP_RIPEMD160);
        roundtrip!(unique, OP_SHA1);
        roundtrip!(unique, OP_SHA256);
        roundtrip!(unique, OP_HASH160);
        roundtrip!(unique, OP_HASH256);
        roundtrip!(unique, OP_CODESEPARATOR);
        roundtrip!(unique, OP_CHECKSIG);
        roundtrip!(unique, OP_CHECKSIGVERIFY);
        roundtrip!(unique, OP_CHECKMULTISIG);
        roundtrip!(unique, OP_CHECKMULTISIGVERIFY);
        roundtrip!(unique, OP_NOP1);
        roundtrip!(unique, OP_CLTV);
        roundtrip!(unique, OP_CSV);
        roundtrip!(unique, OP_NOP4);
        roundtrip!(unique, OP_NOP5);
        roundtrip!(unique, OP_NOP6);
        roundtrip!(unique, OP_NOP7);
        roundtrip!(unique, OP_NOP8);
        roundtrip!(unique, OP_NOP9);
        roundtrip!(unique, OP_NOP10);
        roundtrip!(unique, OP_CHECKSIGADD);
        roundtrip!(unique, OP_RETURN_187);
        roundtrip!(unique, OP_RETURN_188);
        roundtrip!(unique, OP_RETURN_189);
        roundtrip!(unique, OP_RETURN_190);
        roundtrip!(unique, OP_RETURN_191);
        roundtrip!(unique, OP_RETURN_192);
        roundtrip!(unique, OP_RETURN_193);
        roundtrip!(unique, OP_RETURN_194);
        roundtrip!(unique, OP_RETURN_195);
        roundtrip!(unique, OP_RETURN_196);
        roundtrip!(unique, OP_RETURN_197);
        roundtrip!(unique, OP_RETURN_198);
        roundtrip!(unique, OP_RETURN_199);
        roundtrip!(unique, OP_RETURN_200);
        roundtrip!(unique, OP_RETURN_201);
        roundtrip!(unique, OP_RETURN_202);
        roundtrip!(unique, OP_RETURN_203);
        roundtrip!(unique, OP_RETURN_204);
        roundtrip!(unique, OP_RETURN_205);
        roundtrip!(unique, OP_RETURN_206);
        roundtrip!(unique, OP_RETURN_207);
        roundtrip!(unique, OP_RETURN_208);
        roundtrip!(unique, OP_RETURN_209);
        roundtrip!(unique, OP_RETURN_210);
        roundtrip!(unique, OP_RETURN_211);
        roundtrip!(unique, OP_RETURN_212);
        roundtrip!(unique, OP_RETURN_213);
        roundtrip!(unique, OP_RETURN_214);
        roundtrip!(unique, OP_RETURN_215);
        roundtrip!(unique, OP_RETURN_216);
        roundtrip!(unique, OP_RETURN_217);
        roundtrip!(unique, OP_RETURN_218);
        roundtrip!(unique, OP_RETURN_219);
        roundtrip!(unique, OP_RETURN_220);
        roundtrip!(unique, OP_RETURN_221);
        roundtrip!(unique, OP_RETURN_222);
        roundtrip!(unique, OP_RETURN_223);
        roundtrip!(unique, OP_RETURN_224);
        roundtrip!(unique, OP_RETURN_225);
        roundtrip!(unique, OP_RETURN_226);
        roundtrip!(unique, OP_RETURN_227);
        roundtrip!(unique, OP_RETURN_228);
        roundtrip!(unique, OP_RETURN_229);
        roundtrip!(unique, OP_RETURN_230);
        roundtrip!(unique, OP_RETURN_231);
        roundtrip!(unique, OP_RETURN_232);
        roundtrip!(unique, OP_RETURN_233);
        roundtrip!(unique, OP_RETURN_234);
        roundtrip!(unique, OP_RETURN_235);
        roundtrip!(unique, OP_RETURN_236);
        roundtrip!(unique, OP_RETURN_237);
        roundtrip!(unique, OP_RETURN_238);
        roundtrip!(unique, OP_RETURN_239);
        roundtrip!(unique, OP_RETURN_240);
        roundtrip!(unique, OP_RETURN_241);
        roundtrip!(unique, OP_RETURN_242);
        roundtrip!(unique, OP_RETURN_243);
        roundtrip!(unique, OP_RETURN_244);
        roundtrip!(unique, OP_RETURN_245);
        roundtrip!(unique, OP_RETURN_246);
        roundtrip!(unique, OP_RETURN_247);
        roundtrip!(unique, OP_RETURN_248);
        roundtrip!(unique, OP_RETURN_249);
        roundtrip!(unique, OP_RETURN_250);
        roundtrip!(unique, OP_RETURN_251);
        roundtrip!(unique, OP_RETURN_252);
        roundtrip!(unique, OP_RETURN_253);
        roundtrip!(unique, OP_RETURN_254);
        roundtrip!(unique, OP_INVALIDOPCODE);
        assert_eq!(unique.len(), 256);
    }
}
