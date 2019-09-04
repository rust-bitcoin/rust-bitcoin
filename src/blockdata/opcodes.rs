// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Opcodes
//!
//! Bitcoin's script uses a stack-based assembly language. This module defines
//! all of the opcodes
//!

use consensus::encode::{self, Decoder, Encoder};
use consensus::encode::{Decodable, Encodable};

pub use bitcoin::blockdata::opcodes::All;

pub mod all {
    //! Constants associated with All type
    use super::All;

    pub use bitcoin::blockdata::opcodes::all::*;
    /// Does nothing
    pub const OP_NOP2: All = OP_CLTV;
    /// Does nothing
    pub const OP_NOP3: All = OP_CSV;
}

impl<D: Decoder> Decodable<D> for All {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<All, encode::Error> {
        Ok(All::from(d.read_u8()?))
    }
}

impl<S: Encoder> Encodable<S> for All {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        s.emit_u8(self.into_u8())
    }
}

/// Empty stack is also FALSE
pub static OP_FALSE: All = all::OP_PUSHBYTES_0;
/// Number 1 is also TRUE
pub static OP_TRUE: All = all::OP_PUSHNUM_1;
/// check locktime verify
pub static OP_CLTV: All = all::OP_NOP2;
/// check sequence verify
pub static OP_CSV: All = all::OP_NOP3;

pub use bitcoin::blockdata::opcodes::Class;
pub use bitcoin::blockdata::opcodes::Ordinary;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use consensus::encode::{serialize, deserialize};
    use super::*;

    macro_rules! roundtrip {
        ($unique:expr, $op:ident) => {
            assert_eq!(all::$op, All::from(all::$op.into_u8()));

            let s1 = format!("{}", all::$op);
            let s2 = format!("{:?}", all::$op);
            assert_eq!(s1, s2);
            assert_eq!(s1, stringify!($op));
            assert!($unique.insert(s1));

            let enc = serialize(&all::$op);
            assert_eq!(all::$op, deserialize(&enc).unwrap());
        }
    }

    #[test]
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
        roundtrip!(unique, OP_PUSHNUM_NEG1);
        roundtrip!(unique, OP_RESERVED);
        roundtrip!(unique, OP_PUSHNUM_1);
        roundtrip!(unique, OP_PUSHNUM_2);
        roundtrip!(unique, OP_PUSHNUM_3);
        roundtrip!(unique, OP_PUSHNUM_4);
        roundtrip!(unique, OP_PUSHNUM_5);
        roundtrip!(unique, OP_PUSHNUM_6);
        roundtrip!(unique, OP_PUSHNUM_7);
        roundtrip!(unique, OP_PUSHNUM_8);
        roundtrip!(unique, OP_PUSHNUM_9);
        roundtrip!(unique, OP_PUSHNUM_10);
        roundtrip!(unique, OP_PUSHNUM_11);
        roundtrip!(unique, OP_PUSHNUM_12);
        roundtrip!(unique, OP_PUSHNUM_13);
        roundtrip!(unique, OP_PUSHNUM_14);
        roundtrip!(unique, OP_PUSHNUM_15);
        roundtrip!(unique, OP_PUSHNUM_16);
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
        roundtrip!(unique, OP_LESSTHAN );
        roundtrip!(unique, OP_GREATERTHAN );
        roundtrip!(unique, OP_LESSTHANOREQUAL );
        roundtrip!(unique, OP_GREATERTHANOREQUAL );
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
        // Renamed in 0.18.1
        //roundtrip!(unique, OP_NOP2);
        //roundtrip!(unique, OP_NOP3);
        roundtrip!(unique, OP_NOP4);
        roundtrip!(unique, OP_NOP5);
        roundtrip!(unique, OP_NOP6);
        roundtrip!(unique, OP_NOP7);
        roundtrip!(unique, OP_NOP8);
        roundtrip!(unique, OP_NOP9);
        roundtrip!(unique, OP_NOP10);
        roundtrip!(unique, OP_RETURN_186);
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
        roundtrip!(unique, OP_RETURN_255);
        assert_eq!(unique.len(), 254);
    }
}
