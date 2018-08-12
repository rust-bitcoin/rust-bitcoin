// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Script Parsing
//!
//! Representation of a subset of Bitcoin script as an abstract AST which has enough semantic
//! information to determine satisfiability, signature requirements, etc. Is bijective with
//! the subset of script that it maps to.
//!
//! Script descriptors should compile to this AST, as should contracthash templates, rather
//! than going directly to script.
//!

use std::{error, fmt};
use secp256k1;
use util::hash::Hash160;
use util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

use blockdata::script;
use blockdata::opcodes;

/// AST-related error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected(String),
    /// Failed to parse a push as a public key
    BadPubkey(secp256k1::Error),
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadPubkey(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::UnexpectedStart => "unexpected start of script",
            Error::Unexpected(_) => "unexpected token",
            Error::BadPubkey(ref e) => error::Error::description(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
        }
    }

}

/// Atom of a tokenized version of a script
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Token {
    BoolAnd,
    BoolOr,
    Equal,
    EqualVerify,
    CheckSig,
    CheckSigVerify,
    CheckMultiSig,
    CheckMultiSigVerify,
    CheckSequenceVerify,
    FromAltStack,
    ToAltStack,
    Drop,
    Dup,
    If,
    IfDup,
    NotIf,
    Else,
    EndIf,
    Size,
    Swap,
    Tuck,
    Verify,
    Hash160,
    Sha256,
    Number(u32),
    Hash160Hash(Hash160),
    Sha256Hash(Sha256dHash),
    Pubkey(secp256k1::PublicKey),
}

impl Token {
    /// serialize an object into a script
    fn serialize(&self, builder: script::Builder) -> script::Builder {
        match *self {
            Token::BoolAnd => builder.push_opcode(opcodes::All::OP_BOOLAND),
            Token::BoolOr => builder.push_opcode(opcodes::All::OP_BOOLOR),
            Token::Equal => builder.push_opcode(opcodes::All::OP_EQUAL),
            Token::EqualVerify => builder.push_opcode(opcodes::All::OP_EQUALVERIFY),
            Token::CheckSig => builder.push_opcode(opcodes::All::OP_CHECKSIG),
            Token::CheckSigVerify => builder.push_opcode(opcodes::All::OP_CHECKSIGVERIFY),
            Token::CheckMultiSig => builder.push_opcode(opcodes::All::OP_CHECKMULTISIG),
            Token::CheckMultiSigVerify => builder.push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY),
            Token::CheckSequenceVerify => builder.push_opcode(opcodes::OP_CSV),
            Token::FromAltStack => builder.push_opcode(opcodes::All::OP_FROMALTSTACK),
            Token::ToAltStack => builder.push_opcode(opcodes::All::OP_TOALTSTACK),
            Token::Drop => builder.push_opcode(opcodes::All::OP_DROP),
            Token::Dup => builder.push_opcode(opcodes::All::OP_DUP),
            Token::If => builder.push_opcode(opcodes::All::OP_IF),
            Token::IfDup => builder.push_opcode(opcodes::All::OP_IFDUP),
            Token::NotIf => builder.push_opcode(opcodes::All::OP_NOTIF),
            Token::Else => builder.push_opcode(opcodes::All::OP_ELSE),
            Token::EndIf => builder.push_opcode(opcodes::All::OP_ENDIF),
            Token::Size => builder.push_opcode(opcodes::All::OP_SIZE),
            Token::Swap => builder.push_opcode(opcodes::All::OP_SWAP),
            Token::Tuck => builder.push_opcode(opcodes::All::OP_TUCK),
            Token::Verify => builder.push_opcode(opcodes::All::OP_VERIFY),
            Token::Hash160 => builder.push_opcode(opcodes::All::OP_HASH160),
            Token::Sha256 => builder.push_opcode(opcodes::All::OP_SHA256),
            Token::Number(n) => builder.push_int(n as i64),
            Token::Hash160Hash(hash) => builder.push_slice(&hash[..]),
            Token::Sha256Hash(hash) => builder.push_slice(&hash[..]),
            Token::Pubkey(pk) => builder.push_slice(&pk.serialize()[..]),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

#[derive(Debug, Clone)]
/// Iterator that goes through a vector of tokens backward (our parser wants to read
/// backward and this is more efficient anyway since we can use `Vec::pop()`).
struct TokenIter(Vec<Token>);

impl TokenIter {
    fn new(v: Vec<Token>) -> TokenIter {
        TokenIter(v)
    }

    fn peek(&self) -> Option<&Token> {
        self.0.last()
    }

    fn un_next(&mut self, tok: Token) {
        self.0.push(tok)
    }
}

impl Iterator for TokenIter {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        self.0.pop()
    }
}

/// Expression that may be satisfied or dissatisfied; both cases must
/// be non-malleable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum E {
    /// DUP HASH160 <hash> EQUALVERIFY CHECKSIG
    CheckSigHash(Hash160),
    /// <k> <pk...> <len(pk)> CHECKMULTISIG
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    /// <E> <W> ADD ... <W> ADD <k> EQUAL
    Threshold(usize, Box<E>, Vec<W>),
    /// <E> <W> BOOLAND
    ParallelAnd(Box<E>, Box<W>),
    /// <E> IF <F> ELSE 0 ENDIF
    CascadeAnd(Box<E>, Box<F>),
    /// SIZE EQUALVERIFY IF <F> ELSE <E> ENDIF
    SwitchOr(Box<F>, Box<E>),
    /// <E> IFDUP NOTIF <E> ENDIF
    CascadeOr(Box<E>, Box<E>),
    /// <E> <W> BOOLOR
    ParallelOr(Box<E>, Box<W>),
    /// SIZE EQUALVERIFY IF <V> ENDIF 1
    CastV(Box<V>),
    /// M
    CastM(Box<M>),
}

/// Wrapped expression, used as helper for the parallel operations above
#[derive(Debug, Clone, PartialEq, Eq)]
enum W {
    /// SWAP <pk> CHECKSIG
    CheckSig(secp256k1::PublicKey),
    /// SWAP SIZE IF SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1 ENDIF
    HashEqual(Sha256dHash),
    /// TOALTSTACK <E> FROMALTSTACK
    CastE(Box<E>),
}

/// Same conditions as E, plus dissatisfaction must be met by the empty push
#[derive(Debug, Clone, PartialEq, Eq)]
enum M {
    /// <pk> CHECKSIG
    CheckSig(secp256k1::PublicKey),
    /// SIZE IF DUP HASH160 <hash> EQUALVERIFY CHECKSIGVERIFY 1 ENDIF
    CheckSigHash(Hash160),
    /// <k> <pk...> <len(pk)> CHECKMULTISIG
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    /// SIZE IF SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1 ENDIF
    HashEqual(Sha256dHash),
    /// <M> IF <F> ELSE 0 ENDIF
    CascadeAnd(Box<M>, Box<F>),
    /// SIZE EQUALVERIFY NOTIF <F> ELSE 0 ENDIF
    CastF(Box<F>),
}

/// Expression that must succeed and will leave a 1 on the stack after consuming its inputs
#[derive(Debug, Clone, PartialEq, Eq)]
enum F {
    /// <pk> CHECKSIGVERIFY 1
    CheckSig(secp256k1::PublicKey),
    /// <k> <pk...> <len(pk)> CHECKMULTISIGVERIFY 1
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    /// DUP HASH160 <hash> EQVERIFY CHECKSIGVERIFY 1
    CheckSigHash(Hash160),
    /// <n> CSV
    Csv(u32),
    /// SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1
    HashEqual(Sha256dHash),
    /// <E> <W> ADD ... <W> ADD <k> EQUALVERIFY 1
    Threshold(usize, Box<E>, Vec<W>),
    /// <V> <F>
    And(Box<V>, Box<F>),
    /// SIZE EQUALVERIFY IF <F> ELSE <F> ENDIF
    SwitchOr(Box<F>, Box<F>),
    /// SIZE EQUALVERIFY IF <V> ELSE <V> ENDIF 1
    SwitchOrV(Box<V>, Box<V>),
    /// <E> IFDUP NOTIF <F> ENDIF
    CascadeOr(Box<E>, Box<F>),
}

/// Expression that must succeed and will leave nothing on the stack after consuming its inputs
#[derive(Debug, Clone, PartialEq, Eq)]
enum V {
    /// <pk> CHECKSIGVERIFY
    CheckSig(secp256k1::PublicKey),
    /// <k> <pk...> <len(pk)> CHECKMULTISIGVERIFY
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    /// DUP HASH160 <hash> EQVERIFY CHECKSIGVERIFY
    CheckSigHash(Hash160),
    /// <n> CSV DROP
    Csv(u32),
    /// SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY
    HashEqual(Sha256dHash),
    /// <E> <W> ADD ... <W> ADD <k> EQUALVERIFY
    Threshold(usize, Box<E>, Vec<W>),
    /// <V> <V>
    And(Box<V>, Box<V>),
    /// <E> <W> BOOLOR VERIFY
    ParallelOr(Box<E>, Box<W>),
    /// SIZE EQUALVERIFY IF <V> ELSE <V> ENDIF
    SwitchOr(Box<V>, Box<V>),
    /// SIZE EQUALVERIFY IF <F> ELSE <F> ENDIF VERIFY
    SwitchOrF(Box<F>, Box<F>),
    /// <E> NOTIF <V> ENDIF
    CascadeOr(Box<E>, Box<V>),
}

/// "Top" expression, which might succeed or not, or fail or not. Occurs only at the top of a
/// script, such that its failure will fail the entire thing even if it returns a 0.
#[derive(Debug, Clone, PartialEq, Eq)]
enum T {
    /// SIZE 32 EQUALVERIFY SHA256 <hash> EQUAL
    HashEqual(Sha256dHash),
    /// <V> <T>
    And(Box<V>, Box<T>),
    /// SIZE EQUALVERIFY IF <T> ELSE <T> ENDIF
    SwitchOr(Box<T>, Box<T>),
    /// <E> IFDUP NOTIF <T> ENDIF
    CascadeOr(Box<E>, Box<T>),
    /// <E>
    CastE(Box<E>),
    /// <M>
    CastM(Box<M>),
    /// <F>
    CastF(Box<F>),
}

trait AstElem: fmt::Display {
    fn serialize(&self, builder: script::Builder) -> script::Builder;

    fn into_e(self: Box<Self>) -> Result<Box<E>, Error> { Err(Error::Unexpected(self.to_string())) }
    fn into_w(self: Box<Self>) -> Result<Box<W>, Error> { Err(Error::Unexpected(self.to_string())) }
    fn into_m(self: Box<Self>) -> Result<Box<M>, Error> { Err(Error::Unexpected(self.to_string())) }
    fn into_f(self: Box<Self>) -> Result<Box<F>, Error> { Err(Error::Unexpected(self.to_string())) }
    fn into_v(self: Box<Self>) -> Result<Box<V>, Error> { Err(Error::Unexpected(self.to_string())) }
    fn into_t(self: Box<Self>) -> Result<Box<T>, Error> { Err(Error::Unexpected(self.to_string())) }

    fn is_e(&self) -> bool { false }
    fn is_w(&self) -> bool { false }
    fn is_m(&self) -> bool { false }
    fn is_f(&self) -> bool { false }
    fn is_v(&self) -> bool { false }
    fn is_t(&self) -> bool { false }
}

/// Top-level script AST type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTree(Box<T>);

impl ParseTree {
    /// Attempt to parse a script into an AST
    pub fn parse(script: &script::Script) -> Result<ParseTree, script::Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = parse_subexpression(&mut iter)?.into_t()?;
        if let Some(leading) = iter.next() {
            Err(script::Error::Parse(Error::Unexpected(leading.to_string())))
        } else {
            Ok(ParseTree(top))
        }
    }

    /// Serialize an AST into script form
    pub fn serialize(&self) -> script::Script {
        self.0.serialize(script::Builder::new()).into_script()
    }

    /// Compile an instantiated descriptor into a parse tree
    pub fn compile(desc: &script::Descriptor<secp256k1::PublicKey>) -> ParseTree {
        let t = T::from_descriptor(desc, 1.0);
        ParseTree(Box::new(t.ast))
    }
}

/// Tokenize a script
pub fn lex(script: &script::Script) -> Result<Vec<Token>, script::Error> {
    let mut ret = Vec::with_capacity(script.len());
    let secp = secp256k1::Secp256k1::with_caps(secp256k1::ContextFlag::None);

    for ins in script {
        ret.push(match ins {
            script::Instruction::Error(e) => return Err(e),
            script::Instruction::Op(opcodes::All::OP_BOOLAND) => Token::BoolAnd,
            script::Instruction::Op(opcodes::All::OP_BOOLOR) => Token::BoolOr,
            script::Instruction::Op(opcodes::All::OP_EQUAL) => Token::Equal,
            script::Instruction::Op(opcodes::All::OP_EQUALVERIFY) => Token::EqualVerify,
            script::Instruction::Op(opcodes::All::OP_CHECKSIG) => Token::CheckSig,
            script::Instruction::Op(opcodes::All::OP_CHECKSIGVERIFY) => Token::CheckSigVerify,
            script::Instruction::Op(opcodes::All::OP_CHECKMULTISIG) => Token::CheckMultiSig,
            script::Instruction::Op(opcodes::All::OP_CHECKMULTISIGVERIFY) => Token::CheckMultiSigVerify,
            script::Instruction::Op(op) if op == opcodes::OP_CSV => Token::CheckSequenceVerify,
            script::Instruction::Op(opcodes::All::OP_FROMALTSTACK) => Token::FromAltStack,
            script::Instruction::Op(opcodes::All::OP_TOALTSTACK) => Token::ToAltStack,
            script::Instruction::Op(opcodes::All::OP_DROP) => Token::Drop,
            script::Instruction::Op(opcodes::All::OP_DUP) => Token::Dup,
            script::Instruction::Op(opcodes::All::OP_IF) => Token::If,
            script::Instruction::Op(opcodes::All::OP_IFDUP) => Token::IfDup,
            script::Instruction::Op(opcodes::All::OP_NOTIF) => Token::NotIf,
            script::Instruction::Op(opcodes::All::OP_ELSE) => Token::Else,
            script::Instruction::Op(opcodes::All::OP_ENDIF) => Token::EndIf,
            script::Instruction::Op(opcodes::All::OP_SIZE) => Token::Size,
            script::Instruction::Op(opcodes::All::OP_SWAP) => Token::Swap,
            script::Instruction::Op(opcodes::All::OP_TUCK) => Token::Tuck,
            script::Instruction::Op(opcodes::All::OP_VERIFY) => Token::Verify,
            script::Instruction::Op(opcodes::All::OP_HASH160) => Token::Hash160,
            script::Instruction::Op(opcodes::All::OP_SHA256) => Token::Sha256,
            script::Instruction::PushBytes(bytes) => {
                match bytes.len() {
                    20 => Token::Hash160Hash(Hash160::from(bytes)),
                    32 => Token::Sha256Hash(Sha256dHash::from(bytes)),
                    33 => Token::Pubkey(secp256k1::PublicKey::from_slice(&secp, bytes).map_err(Error::BadPubkey)?),
                    _ => {
                        match script::read_scriptint(bytes) {
                            Ok(v) if v >= 0 => {
                                // check minimality of the number
                                if &script::Builder::new().push_int(v).into_script()[1..] != bytes {
                                    return Err(script::Error::InvalidPush(bytes.to_owned()));
                                }
                                Token::Number(v as u32)
                            }
                            Ok(_) => return Err(script::Error::InvalidPush(bytes.to_owned())),
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            script::Instruction::Op(opcodes::All::OP_PUSHBYTES_0) => Token::Number(0),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_1) => Token::Number(1),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_2) => Token::Number(2),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_3) => Token::Number(3),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_4) => Token::Number(4),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_5) => Token::Number(5),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_6) => Token::Number(6),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_7) => Token::Number(7),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_8) => Token::Number(8),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_9) => Token::Number(9),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_10) => Token::Number(10),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_11) => Token::Number(11),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_12) => Token::Number(12),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_13) => Token::Number(13),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_14) => Token::Number(14),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_15) => Token::Number(15),
            script::Instruction::Op(opcodes::All::OP_PUSHNUM_16) => Token::Number(16),
            script::Instruction::Op(op) => return Err(script::Error::InvalidOpcode(op)),
        });
    }
    Ok(ret)
}

macro_rules! into_fn(
    (E) => (AstElem::into_e);
    (M) => (AstElem::into_m);
    (W) => (AstElem::into_w);
    (V) => (AstElem::into_v);
    (F) => (AstElem::into_f);
    (T) => (AstElem::into_t);
);

macro_rules! is_fn(
    (E) => (AstElem::is_e);
    (M) => (AstElem::is_m);
    (W) => (AstElem::is_w);
    (V) => (AstElem::is_v);
    (F) => (AstElem::is_f);
    (T) => (AstElem::is_t);
);

macro_rules! expect_token(
    ($tokens:expr, $expected:pat => $b:block) => ({
        match $tokens.next() {
            Some($expected) => $b,
            Some(tok) => return Err(Error::Unexpected(tok.to_string())),
            None => return Err(Error::UnexpectedStart),
        }
    });
    ($tokens:expr, $expected:pat) => (expect_token!($tokens, $expected => {}));
);

macro_rules! parse_tree(
    // Tree
    (
        // list of tokens passed into macro scope
        $tokens:expr,
        // list of expected tokens
        $($expected:pat $(, $more:pat)* => { $($sub:tt)* }),*
        // list of expected subexpressions. The whole thing is surrounded
        // in a $(..)* because it's optional. But it should only be used once.
        $(
        #subexpression $($parse_expected:tt: $name:ident $(, $parse_more:pat)* => { $($parse_sub:tt)* }),*
        )*
    ) => ({
        match $tokens.next() {
            $(Some($expected) => {
                $(expect_token!($tokens, $more);)*
                parse_tree!($tokens, $($sub)*)
            },)*
            Some(tok) => {
                #[allow(unused_assignments)]
                #[allow(unused_mut)]
                let mut ret: Result<Box<AstElem>, Error> = Err(Error::Unexpected(tok.to_string()));
                $(
                $tokens.un_next(tok);
                let subexpr = parse_subexpression($tokens)?;
                ret =
                $(if is_fn!($parse_expected)(&*subexpr) {
                    let $name = into_fn!($parse_expected)(subexpr).unwrap();
                    $(expect_token!($tokens, $parse_more);)*
                    parse_tree!($tokens, $($parse_sub)*)
                } else)* {
                    Err(Error::Unexpected(subexpr.to_string()))
                };
                )*
                ret
            }
            None => return Err(Error::UnexpectedStart),
        }
    });
    // Not a tree; must be a block
    ($tokens:expr, $($b:tt)*) => ({ $($b)* });
);


/// Parse a subexpression that is -not- a wexpr (wexpr is special-cased
/// to avoid splitting expr into expr0 and exprn in the AST structure).
fn parse_subexpression(tokens: &mut TokenIter) -> Result<Box<AstElem>, Error> {
    if let Some(tok) = tokens.next() {
        tokens.un_next(tok);
    }
    let ret: Result<Box<AstElem>, Error> = parse_tree!(tokens,
        Token::BoolAnd => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(Box::new(E::ParallelAnd(expr, wexpr)))
                }
            }
        },
        Token::BoolOr => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(Box::new(E::ParallelOr(expr, wexpr)))
                }
            }
        },
        Token::Equal => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(Box::new(T::HashEqual(hash)))
            },
            Token::Number(k) => {{
                let mut ws = vec![];
                let e;
                loop {
                    let next_sub = parse_subexpression(tokens)?;
                    if next_sub.is_w() {
                        ws.push(*next_sub.into_w().unwrap());
                    } else if next_sub.is_e() {
                        e = next_sub.into_e().unwrap();
                        break;
                    } else {
                        return Err(Error::Unexpected(next_sub.to_string()));
                    }
                }
                Ok(Box::new(E::Threshold(k as usize, e, ws)))
            }}
        },
        Token::EqualVerify => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(Box::new(V::HashEqual(hash)))
            },
            Token::Number(k) => {{
                let mut ws = vec![];
                let e;
                loop {
                    let next_sub = parse_subexpression(tokens)?;
                    if next_sub.is_w() {
                        ws.push(*next_sub.into_w().unwrap());
                    } else if next_sub.is_e() {
                        e = next_sub.into_e().unwrap();
                        break;
                    } else {
                        return Err(Error::Unexpected(next_sub.to_string()));
                    }
                }
                Ok(Box::new(V::Threshold(k as usize, e, ws)))
            }}
        },
        Token::CheckSig => {
            Token::EqualVerify => {
                Token::Hash160Hash(hash), Token::Hash160, Token::Dup => {
                    Ok(Box::new(E::CheckSigHash(hash)))
                }
            },
            Token::Pubkey(pk) => {{
                match tokens.next() {
                    Some(Token::Swap) => Ok(Box::new(W::CheckSig(pk))),
                    Some(x) => {
                        tokens.un_next(x);
                        Ok(Box::new(M::CheckSig(pk)))
                    }
                    None => Ok(Box::new(M::CheckSig(pk))),
                }
            }}
        },
        Token::CheckSigVerify => {
            Token::EqualVerify => {
                Token::Hash160Hash(hash), Token::Hash160, Token::Dup => {
                    Ok(Box::new(V::CheckSigHash(hash)))
                }
            },
            Token::Pubkey(pk) => {
                Ok(Box::new(V::CheckSig(pk)))
            }
        },
        Token::CheckMultiSig => {{
            let n = expect_token!(tokens, Token::Number(n) => { n });
            let mut pks = vec![];
            for _ in 0..n {
                pks.push(expect_token!(tokens, Token::Pubkey(pk) => { pk }));
            }
            pks.reverse();
            let k = expect_token!(tokens, Token::Number(n) => { n });
            Ok(Box::new(E::CheckMultiSig(k as usize, pks)))
        }},
        Token::CheckMultiSigVerify => {{
            let n = expect_token!(tokens, Token::Number(n) => { n });
            let mut pks = vec![];
            for _ in 0..n {
                pks.push(expect_token!(tokens, Token::Pubkey(pk) => { pk }));
            }
            pks.reverse();
            let k = expect_token!(tokens, Token::Number(n) => { n });
            Ok(Box::new(V::CheckMultiSig(k as usize, pks)))
        }},
        Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(Box::new(F::Csv(n)))
            }
        },
        Token::FromAltStack => {
            #subexpression
            E: expr, Token::ToAltStack => {
                Ok(Box::new(W::CastE(expr)))
            }
        },
        Token::Drop, Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(Box::new(V::Csv(n)))
            }
        },
        Token::EndIf => {
            Token::Number(0), Token::Else => {
                #subexpression
                F: fexpr => {
                    Token::NotIf => {
                        Token::EqualVerify, Token::Size => {
                            Ok(Box::new(M::CastF(fexpr)))
                        }
                        #subexpression
                        M: left => {
                            Ok(Box::new(M::CascadeAnd(left, fexpr)))
                        },
                        E: left => {
                            Ok(Box::new(E::CascadeAnd(left, fexpr)))
                        }
                    }
                }
            }
            #subexpression
            E: right => {
                Token::Else => {
                    #subexpression
                    F: left, Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(E::SwitchOr(left, right)))
                    }
                },
                Token::NotIf, Token::IfDup => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(E::CascadeOr(left, right)))
                    }
                }
            },
            F: right => {
                Token::If, Token::Size => {{
                    match *right {
                        F::CheckSigHash(hash) => Ok(Box::new(M::CheckSigHash(hash))),
                        F::CheckMultiSig(k, keys) => Ok(Box::new(M::CheckMultiSig(k, keys))),
                        F::HashEqual(hash) => {
                            match tokens.next() {
                                Some(Token::Swap) => Ok(Box::new(W::HashEqual(hash))),
                                Some(x) => {
                                    tokens.un_next(x);
                                    Ok(Box::new(M::HashEqual(hash)))
                                }
                                None => Ok(Box::new(M::HashEqual(hash))),
                            }
                        }
                        x => Err(Error::Unexpected(x.to_string())),
                    }
                }},
                Token::Else => {
                    #subexpression
                    F: left, Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(F::SwitchOr(left, right)))
                    }
                },
                Token::NotIf, Token::IfDup => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(F::CascadeOr(left, right)))
                    }
                }
            },
            V: right => {
                Token::Else => {
                    #subexpression
                    V: left, Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(V::SwitchOr(left, right)))
                    }
                },
                Token::NotIf => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(V::CascadeOr(left, right)))
                    }
                }
            },
            T: right => {
                Token::Else => {
                    #subexpression
                    T: left, Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(T::SwitchOr(left, right)))
                    }
                },
                Token::NotIf, Token::IfDup => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(T::CascadeOr(left, right)))
                    }
                }
            }
        },
        Token::Verify => { 
            Token::EndIf => {
                #subexpression
                F: right, Token::Else => {
                    #subexpression
                    F: left, Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(V::SwitchOrF(left, right)))
                    }
                }
            },
            Token::BoolOr => {
                #subexpression
                W: wexpr => {
                    #subexpression
                    E: expr => {
                        Ok(Box::new(V::ParallelOr(expr, wexpr)))
                    }
                }
            }
        },
        Token::Number(1) => {
            Token::EndIf => {
                #subexpression
                V: right => {
                    Token::Else => {
                        #subexpression
                        V: left, Token::If, Token::EqualVerify, Token::Size => {
                            Ok(Box::new(F::SwitchOrV(left, right)))
                        }
                    },
                    Token::If, Token::EqualVerify, Token::Size => {
                        Ok(Box::new(E::CastV(right)))
                    }
                }
            }
            #subexpression
            V: vexpr => {{
                let unboxed = *vexpr; // need this variable, cannot directly match on *vexpr, see https://github.com/rust-lang/rust/issues/16223
                match unboxed {
                    V::CheckSig(pk) => Ok(Box::new(F::CheckSig(pk))),
                    V::CheckSigHash(hash) => Ok(Box::new(F::CheckSigHash(hash))),
                    V::CheckMultiSig(k, keys) => Ok(Box::new(F::CheckMultiSig(k, keys))),
                    V::HashEqual(hash) => Ok(Box::new(F::HashEqual(hash))),
                    V::Threshold(k, e, ws) => Ok(Box::new(F::Threshold(k, e, ws))),
                    x => Err(Error::Unexpected(x.to_string())),
                }
            }}
        }
    );

    if let Ok(ret) = ret {
        // vexpr [tfv]expr AND
        if ret.is_t() || ret.is_f() || ret.is_v() {
            match tokens.peek() {
                None | Some(&Token::If) | Some(&Token::NotIf) | Some(&Token::Else) => Ok(ret),
                _ => {
                    let left = parse_subexpression(tokens)?.into_v()?;

                    if ret.is_t() {
                        let right = ret.into_t().unwrap();
                        Ok(Box::new(T::And(left, right)))
                    } else if ret.is_f() {
                        let right = ret.into_f().unwrap();
                        Ok(Box::new(F::And(left, right)))
                    } else if ret.is_v() {
                        let right = ret.into_v().unwrap();
                        Ok(Box::new(V::And(left, right)))
                    } else {
                        unreachable!()
                    }
                }
            }
        } else {
            Ok(ret)
        }
    } else {
        ret
    }
}

struct Cost<T> {
    ast: T,
    pk_cost: usize,
    sat_cost: usize,
    dissat_cost: usize,
}

impl fmt::Display for E {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for E {
    fn into_e(self: Box<E>) -> Result<Box<E>, Error> { Ok(self) }
    fn into_t(self: Box<E>) -> Result<Box<T>, Error> { Ok(Box::new(T::CastE(self))) }
    fn is_e(&self) -> bool { true }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            E::CheckSigHash(ref hash) => {
                builder.push_opcode(opcodes::All::OP_DUP)
                       .push_opcode(opcodes::All::OP_HASH160)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_CHECKSIG)
            }
            E::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIG)
            }
            E::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::All::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::All::OP_EQUAL)
            }
            E::ParallelAnd(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_BOOLAND)
            }
            E::CascadeAnd(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_IF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ELSE)
                       .push_int(0)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            E::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            E::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_IFDUP)
                                 .push_opcode(opcodes::All::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            E::ParallelOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_BOOLOR)
            }
            E::CastV(ref vexpr) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                vexpr.serialize(builder).push_opcode(opcodes::All::OP_ENDIF)
                                        .push_int(1)
            }
            E::CastM(ref mexpr) => mexpr.serialize(builder)
        }
    }
}

fn min_cost<T, S, F: FnOnce(S) -> T>(one: Cost<T>, two: Cost<S>, sat_prob: f64, cast: F) -> Cost<T> {
    let weight_one = one.pk_cost as f64 + sat_prob * one.sat_cost as f64 + (1.0 - sat_prob) * one.dissat_cost as f64;
    let weight_two = two.pk_cost as f64 + sat_prob * two.sat_cost as f64 + (1.0 - sat_prob) * two.dissat_cost as f64;
    if weight_one < weight_two {
        one
    } else {
        Cost {
            ast: cast(two.ast),
            pk_cost: two.pk_cost,
            sat_cost: two.sat_cost,
            dissat_cost: two.dissat_cost,
        }
    }
}

macro_rules! compare_rules(
    ($sat_prob:expr, $left:expr, $right:expr;
     $($L:ident: $lty:ident, $lweight:expr; $R:ident: $rty:ident, $rweight:expr; $pk_cost:expr, $sat_cost:expr, $dissat_cost:expr; $result:expr;)*
    ) => ({
        let mut ret = vec![];
        $({
        #[allow(non_snake_case)]
        let $L = $lty::from_descriptor($left, $lweight);
        #[allow(non_snake_case)]
        let $R = $rty::from_descriptor($right, $rweight);

        ret.push(Cost {
            ast: $result,
            pk_cost: $pk_cost,
            sat_cost: $sat_cost,
            dissat_cost: $dissat_cost,
        });
        })*

        let last = ret.pop().unwrap();
        ret.into_iter().fold(last, |acc, n| min_cost(acc, n, $sat_prob, |x| x))
    })
);

impl E {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<E> {
        match *desc {
            script::Descriptor::Key(_) | script::Descriptor::Time(_) | script::Descriptor::Hash(_) => {
                let mcost = M::from_descriptor(desc, satisfaction_probability);
                Cost {
                    ast: E::CastM(Box::new(mcost.ast)),
                    pk_cost: mcost.pk_cost,
                    sat_cost: mcost.sat_cost,
                    dissat_cost: mcost.sat_cost,
                }
            }
            script::Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: E::CheckSigHash(hash),
                    pk_cost: 25,
                    sat_cost: 34 + 73,
                    dissat_cost: 34 + 1,
                }
            }
            script::Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: E::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1 + 73*k,
                    dissat_cost: 1 + k,
                }
            }
            script::Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let e = E::from_descriptor(&exprs[0], satisfaction_probability * k as f64 / exprs.len() as f64);
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let w = W::from_descriptor(expr, satisfaction_probability * k as f64 / exprs.len() as f64);
                    pk_cost += w.pk_cost;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                Cost {
                    ast: E::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * k / exprs.len(),  // TODO is simply averaging here the right thing to do?
                    dissat_cost: dissat_cost * k / exprs.len(),
                }
            }
            script::Descriptor::And(ref left, ref right) => {
                let e = compare_rules!(satisfaction_probability, left, right;
                    // e1 w2 BOOLAND
                    L: E, satisfaction_probability; R: W, satisfaction_probability;
                    L.pk_cost + R.pk_cost + 1,
                    L.sat_cost + R.sat_cost,
                    L.dissat_cost + R.dissat_cost;
                    E::ParallelAnd(Box::new(L.ast), Box::new(R.ast));
                    // e2 w1 BOOLAND
                    L: W, satisfaction_probability; R: E, satisfaction_probability;
                    L.pk_cost + R.pk_cost + 1,
                    L.sat_cost + R.sat_cost,
                    L.dissat_cost + R.dissat_cost;
                    E::ParallelAnd(Box::new(R.ast), Box::new(L.ast));
                    // e1 IF f2 ELSE 0 ENDIF
                    L: E, satisfaction_probability; R: F, 1.0;
                    L.pk_cost + R.pk_cost + 4,
                    L.sat_cost + R.sat_cost,
                    L.dissat_cost;
                    E::CascadeAnd(Box::new(L.ast), Box::new(R.ast));
                    // e2 IF f1 ELSE 0 ENDIF
                    L: F, 1.0; R: E, satisfaction_probability;
                    L.pk_cost + R.pk_cost + 4,
                    L.sat_cost + R.sat_cost,
                    R.dissat_cost;
                    E::CascadeAnd(Box::new(R.ast), Box::new(L.ast));
                );
                // Take minimum of this and the M result
                let m = M::from_descriptor(desc, satisfaction_probability);
                min_cost(e, m, satisfaction_probability, |m| E::CastM(Box::new(m)))
            }
            script::Descriptor::Or(_, _) => unimplemented!(),
            script::Descriptor::AsymmetricOr(ref left, ref right) => {
                let e = compare_rules!(satisfaction_probability, left, right;
                    // e1 w2 BOOLOR
                    L: E, satisfaction_probability; R: W, 0.0;
                    L.pk_cost + R.pk_cost + 1,
                    L.sat_cost + R.dissat_cost,
                    L.dissat_cost + R.dissat_cost;
                    E::ParallelOr(Box::new(L.ast), Box::new(R.ast));
                    // e2 w1 BOOLOR
                    L: W, satisfaction_probability; R: E, 0.0;
                    L.pk_cost + R.pk_cost + 1,
                    L.sat_cost + R.dissat_cost,
                    L.dissat_cost + R.dissat_cost;
                    E::ParallelOr(Box::new(R.ast), Box::new(L.ast));
                );
                // Take minimum of this and the M result
                let m = M::from_descriptor(desc, satisfaction_probability);
                min_cost(e, m, satisfaction_probability, |m| E::CastM(Box::new(m)))
            }
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

impl fmt::Display for W {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for W {
    fn into_w(self: Box<W>) -> Result<Box<W>, Error> { Ok(self) }
    fn is_w(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            W::CheckSig(pk) => {
                builder.push_opcode(opcodes::All::OP_SWAP)
                       .push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIG)
            }
            W::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SWAP)
                       .push_opcode(opcodes::All::OP_SIZE)
                       .push_opcode(opcodes::All::OP_IF)
                       .push_opcode(opcodes::All::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_int(1)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            W::CastE(ref expr) => {
                builder = builder.push_opcode(opcodes::All::OP_TOALTSTACK);
                expr.serialize(builder).push_opcode(opcodes::All::OP_FROMALTSTACK)
            }
        }
    }
}

impl W {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<W> {
        match *desc {
            script::Descriptor::Key(ref key) => {
                Cost {
                    ast: W::CheckSig(key.clone()),
                    pk_cost: 36,
                    sat_cost: 73,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::Hash(hash) => {
                Cost {
                    ast: W::HashEqual(hash),
                    pk_cost: 32,
                    sat_cost: 33,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::KeyHash(_) | script::Descriptor::Time(_) |
            script::Descriptor::Multi(_, _) | script::Descriptor::And(_, _) |
            script::Descriptor::Or(_, _) | script::Descriptor::AsymmetricOr(_, _) |
            script::Descriptor::Threshold(_, _) => {
                let e = E::from_descriptor(desc, satisfaction_probability);
                Cost {
                    ast: W::CastE(Box::new(e.ast)),
                    pk_cost: e.pk_cost + 2,
                    sat_cost: e.sat_cost,
                    dissat_cost: e.sat_cost,
                }
            }
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}
impl fmt::Display for M {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for M {
    fn into_m(self: Box<M>) -> Result<Box<M>, Error> { Ok(self) }
    fn into_e(self: Box<M>) -> Result<Box<E>, Error> { Ok(Box::new(E::CastM(self))) }
    fn into_t(self: Box<M>) -> Result<Box<T>, Error> { Ok(Box::new(T::CastM(self))) }
    fn is_m(&self) -> bool { true }
    fn is_e(&self) -> bool { true }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            M::CheckSig(ref pk) => {
                builder.push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIG)
            }
            M::CheckSigHash(hash) => {
                builder.push_opcode(opcodes::All::OP_SIZE)
                       .push_opcode(opcodes::All::OP_IF)
                       .push_opcode(opcodes::All::OP_DUP)
                       .push_opcode(opcodes::All::OP_HASH160)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
                       .push_int(1)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            M::CheckMultiSig(k, ref pks) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_IF)
                                 .push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                       .push_int(1)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            M::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SIZE)
                       .push_opcode(opcodes::All::OP_IF)
                       .push_opcode(opcodes::All::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_int(1)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            M::CascadeAnd(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_IF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ELSE)
                       .push_int(0)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
            M::CastF(ref fexpr) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_NOTIF);
                builder = fexpr.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ELSE)
                       .push_int(0)
                       .push_opcode(opcodes::All::OP_ENDIF)
            }
        }
    }
}

impl M {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<M> {
        match *desc {
            script::Descriptor::Key(ref key) => {
                Cost {
                    ast: M::CheckSig(key.clone()),
                    pk_cost: 35,
                    sat_cost: 73,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: M::CheckSigHash(hash),
                    pk_cost: 29,
                    sat_cost: 34 + 73,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: M::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 5,
                    sat_cost: 1 + 73*k,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::Hash(hash) => {
                Cost {
                    ast: M::HashEqual(hash),
                    pk_cost: 31,
                    sat_cost: 33,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::And(ref left, ref right) => {
                compare_rules!(satisfaction_probability, left, right;
                    // m1 IF f2 ELSE 0 ENDIF
                    L: M, satisfaction_probability; R: F, 1.0;
                    L.pk_cost + R.pk_cost + 4,
                    L.sat_cost + R.sat_cost,
                    L.dissat_cost;
                    M::CascadeAnd(Box::new(L.ast), Box::new(R.ast));
                    // m2 IF f1 ELSE 0 ENDIF
                    L: F, 1.0; R: M, satisfaction_probability;
                    L.pk_cost + R.pk_cost + 4,
                    L.sat_cost + R.sat_cost,
                    R.dissat_cost;
                    M::CascadeAnd(Box::new(R.ast), Box::new(L.ast));
                    // SIZE EQUALVERIFY IF v1 f2 ELSE 0 ENDIF
                    L: V, 1.0; R: F, 1.0;
                    L.pk_cost + R.pk_cost + 6,
                    L.sat_cost + R.sat_cost,
                    1;
                    M::CastF(Box::new(F::And(Box::new(L.ast), Box::new(R.ast))));
                    // SIZE EQUALVERIFY IF v2 f1 ELSE 0 ENDIF
                    L: F, 1.0; R: V, 1.0;
                    L.pk_cost + R.pk_cost + 6,
                    L.sat_cost + R.sat_cost,
                    1;
                    M::CastF(Box::new(F::And(Box::new(R.ast), Box::new(L.ast))));
                )
            }
            script::Descriptor::Time(_) |
            script::Descriptor::Or(_, _) |
            script::Descriptor::AsymmetricOr(_, _) |
            script::Descriptor::Threshold(_, _) => {
                let f = F::from_descriptor(desc, 1.0);
                Cost {
                    ast: M::CastF(Box::new(f.ast)),
                    pk_cost: f.pk_cost + 6,
                    sat_cost: f.sat_cost + 1,
                    dissat_cost: 2,
                }
            }
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

impl fmt::Display for F {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for F {
    fn into_f(self: Box<F>) -> Result<Box<F>, Error> { Ok(self) }
    fn into_t(self: Box<F>) -> Result<Box<T>, Error> { Ok(Box::new(T::CastF(self))) }
    fn is_f(&self) -> bool { true }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            F::CheckSig(ref pk) => {
                builder.push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
                       .push_int(1)
            }
            F::CheckSigHash(hash) => {
                builder.push_opcode(opcodes::All::OP_DUP)
                       .push_opcode(opcodes::All::OP_HASH160)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
                       .push_int(1)
            }
            F::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                       .push_int(1)
            }
            F::Csv(n) => {
                builder.push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
            }
            F::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::All::OP_EQUAL)
                       .push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_int(1)
            }
            F::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::All::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_int(1)
            }
            F::And(ref left, ref right) => {
                builder = left.serialize(builder);
                right.serialize(builder)
            }
            F::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            F::SwitchOrV(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
                       .push_int(1)
            }
            F::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_IFDUP)
                                 .push_opcode(opcodes::All::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
        }
    }
}

impl F {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<F> {
        debug_assert_eq!(satisfaction_probability, 1.0);
        match *desc {
            script::Descriptor::Key(ref key) => {
                Cost {
                    ast: F::CheckSig(key.clone()),
                    pk_cost: 36,
                    sat_cost: 73,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: F::CheckSigHash(hash),
                    pk_cost: 26,
                    sat_cost: 34 + 73,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: F::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 2,
                    sat_cost: 1 + 73*k,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let e = E::from_descriptor(&exprs[0], satisfaction_probability * k as f64 / exprs.len() as f64);
                let mut pk_cost = 2 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let w = W::from_descriptor(expr, satisfaction_probability * k as f64 / exprs.len() as f64);
                    pk_cost += w.pk_cost;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                Cost {
                    ast: F::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * k / exprs.len(),  // TODO is simply averaging here the right thing to do?
                    dissat_cost: dissat_cost * k / exprs.len(),
                }
            }
            script::Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: F::Csv(n),
                    pk_cost: 1 + num_cost,
                    sat_cost: 0,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Hash(hash) => {
                Cost {
                    ast: F::HashEqual(hash),
                    pk_cost: 28,
                    sat_cost: 33,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::And(ref left, ref right) => {
                let vl = V::from_descriptor(left, satisfaction_probability);
                let vr = V::from_descriptor(right, satisfaction_probability);
                let fl = F::from_descriptor(left, satisfaction_probability);
                let fr = F::from_descriptor(right, satisfaction_probability);

                if vl.pk_cost + fr.pk_cost + vl.sat_cost + fr.sat_cost <
                   vr.pk_cost + fl.pk_cost + vr.sat_cost + fl.sat_cost {
                    Cost {
                        ast: F::And(Box::new(vl.ast), Box::new(fr.ast)),
                        pk_cost: vl.pk_cost + fr.pk_cost,
                        sat_cost: vl.sat_cost + fr.sat_cost,
                        dissat_cost: 0,
                    }
                } else {
                    Cost {
                        ast: F::And(Box::new(vr.ast), Box::new(fl.ast)),
                        pk_cost: vr.pk_cost + fl.pk_cost,
                        sat_cost: vr.sat_cost + fl.sat_cost,
                        dissat_cost: 0,
                    }
                }
            }
            script::Descriptor::Or(_, _) => unimplemented!(),
            script::Descriptor::AsymmetricOr(ref left, ref right) => {
                compare_rules!(satisfaction_probability, left, right;
                    // e1 IFDUP NOTIF f2 ENDIF
                    L: E, satisfaction_probability; R: F, 1.0;
                    L.pk_cost + R.pk_cost + 3,
                    L.sat_cost,
                    0;
                    F::CascadeOr(Box::new(L.ast), Box::new(R.ast));
                    // SIZE EQUALVERIFY IF f2 ELSE f1 ENDIF
                    L: F, 1.0; R: F, 1.0;
                    L.pk_cost + R.pk_cost + 5,
                    L.sat_cost + 1,
                    0;
                    F::SwitchOr(Box::new(R.ast), Box::new(L.ast));
                )
            }
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}


impl fmt::Display for V {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for V {
    fn into_v(self: Box<V>) -> Result<Box<V>, Error> { Ok(self) }
    fn is_v(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            V::CheckSig(ref pk) => {
                builder.push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
            }
            V::CheckSigHash(hash) => {
                builder.push_opcode(opcodes::All::OP_DUP)
                       .push_opcode(opcodes::All::OP_HASH160)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
            }
            V::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
            }
            V::Csv(n) => {
                builder.push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
                       .push_opcode(opcodes::All::OP_DROP)
            }
            V::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::All::OP_EQUAL)
                       .push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
            }
            V::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::All::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
            }
            V::And(ref left, ref right) => {
                builder = left.serialize(builder);
                right.serialize(builder)
            }
            V::ParallelOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_BOOLOR)
                       .push_opcode(opcodes::All::OP_VERIFY)
            }
            V::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            V::SwitchOrF(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
                       .push_opcode(opcodes::All::OP_VERIFY)
            }
            V::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
        }
    }
}

impl V {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<V> {
        debug_assert_eq!(satisfaction_probability, 1.0);
        match *desc {
            script::Descriptor::Key(ref key) => {
                Cost {
                    ast: V::CheckSig(key.clone()),
                    pk_cost: 35,
                    sat_cost: 73,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: V::CheckSigHash(hash),
                    pk_cost: 25,
                    sat_cost: 34 + 73,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: V::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1 + 73*k,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: V::Csv(n),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Hash(hash) => {
                Cost {
                    ast: V::HashEqual(hash),
                    pk_cost: 27,
                    sat_cost: 33,
                    dissat_cost: 1,
                }
            }
            script::Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let e = E::from_descriptor(&exprs[0], satisfaction_probability * k as f64 / exprs.len() as f64);
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let w = W::from_descriptor(expr, satisfaction_probability * k as f64 / exprs.len() as f64);
                    pk_cost += w.pk_cost;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                Cost {
                    ast: V::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * k / exprs.len(),  // TODO is simply averaging here the right thing to do?
                    dissat_cost: dissat_cost * k / exprs.len(),
                }
            }
            script::Descriptor::And(ref left, ref right) => {
                let l = V::from_descriptor(left, satisfaction_probability);
                let r = V::from_descriptor(right, satisfaction_probability);
                Cost {
                    pk_cost: l.pk_cost + r.pk_cost,
                    sat_cost: l.sat_cost + r.sat_cost,
                    dissat_cost: 0,
                    ast: V::And(Box::new(l.ast), Box::new(r.ast)),
                }
            }
            script::Descriptor::Or(_, _) => unimplemented!(),
            script::Descriptor::AsymmetricOr(_, _) => unimplemented!(),
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

impl fmt::Display for T {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = self.serialize(script::Builder::new()).into_script();
        fmt::Display::fmt(&script, f)
    }
}

impl AstElem for T {
    fn into_t(self: Box<T>) -> Result<Box<T>, Error> { Ok(self) }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            T::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
                       .push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUAL)
            }
            T::And(ref vexpr, ref top) => {
                builder = vexpr.serialize(builder);
                top.serialize(builder)
            }
            T::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_SIZE)
                                 .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                 .push_opcode(opcodes::All::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            T::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::All::OP_IFDUP)
                                 .push_opcode(opcodes::All::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            T::CastE(ref expr) => expr.serialize(builder),
            T::CastM(ref expr) => expr.serialize(builder),
            T::CastF(ref expr) => expr.serialize(builder),
        }
    }
}

impl T {
    fn from_descriptor(desc: &script::Descriptor<secp256k1::PublicKey>, satisfaction_probability: f64) -> Cost<T> {
        debug_assert_eq!(satisfaction_probability, 1.0);

        match *desc {
            script::Descriptor::Key(_) | script::Descriptor::KeyHash(_) | script::Descriptor::Multi(_, _) => {
                let e = E::from_descriptor(desc, satisfaction_probability);
                Cost {
                    ast: T::CastE(Box::new(e.ast)),
                    pk_cost: e.pk_cost,
                    sat_cost: e.sat_cost,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Time(_) => {
                let f = F::from_descriptor(desc, satisfaction_probability);
                Cost {
                    ast: T::CastF(Box::new(f.ast)),
                    pk_cost: f.pk_cost,
                    sat_cost: f.sat_cost,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::Hash(hash) => {
                Cost {
                    ast: T::HashEqual(hash),
                    pk_cost: 27,
                    sat_cost: 33,
                    dissat_cost: 0,
                }
            }
            script::Descriptor::And(_, _) |
            script::Descriptor::Or(_, _) |
            script::Descriptor::AsymmetricOr(_, _) |
            script::Descriptor::Threshold(_, _) => {
                let e = E::from_descriptor(desc, 1.0);
                let f = F::from_descriptor(desc, 1.0);
                if e.pk_cost + e.sat_cost < f.pk_cost + f.sat_cost {
                    Cost {
                        ast: T::CastE(Box::new(e.ast)),
                        pk_cost: e.pk_cost,
                        sat_cost: e.sat_cost,
                        dissat_cost: 0,
                    }
                } else {
                    Cost {
                        ast: T::CastF(Box::new(f.ast)),
                        pk_cost: f.pk_cost,
                        sat_cost: f.sat_cost,
                        dissat_cost: 0,
                    }
                }
            }
            script::Descriptor::Wpkh(_) | script::Descriptor::Sh(_) | script::Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

    use secp256k1;

    fn pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
            ).expect("public key");
            ret.push(pk);
        }
        ret
    }

    fn roundtrip(tree: &ParseTree, s: &str) {
        let ser = tree.serialize();
        assert_eq!(ser.to_string(), s);
        let deser = ParseTree::parse(&ser).expect("deserialize result of serialize");
        assert_eq!(tree, &deser);
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(5);

        roundtrip(
            &ParseTree(Box::new(T::CastM(Box::new(M::CheckSig(keys[0].clone()))))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &ParseTree(Box::new(T::CastE(Box::new(E::CheckMultiSig(3, keys.clone()))))),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        let hash = Hash160::from_data(&keys[0].serialize());
        roundtrip(
            &ParseTree(Box::new(T::CastE(Box::new(E::CheckSigHash(hash))))),
            "Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 60afcdec519698a263417ddfe7cea936737a0ee7 OP_EQUALVERIFY OP_CHECKSIG)"
        );

        // Liquid policy
        roundtrip(
            &ParseTree(Box::new(T::CascadeOr(
                Box::new(E::CheckMultiSig(2, keys[0..2].to_owned())),
                Box::new(T::And(
                     Box::new(V::CheckMultiSig(2, keys[3..5].to_owned())),
                     Box::new(T::CastF(Box::new(F::Csv(10000)))),
                 )),
             ))),
             "Script(OP_PUSHNUM_2 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                                  OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                                  OP_PUSHNUM_2 OP_CHECKMULTISIG \
                     OP_IFDUP OP_NOTIF \
                         OP_PUSHNUM_2 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                                      OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                                      OP_PUSHNUM_2 OP_CHECKMULTISIGVERIFY \
                         OP_PUSHBYTES_2 1027 OP_NOP3 \
                     OP_ENDIF)"
         );

        roundtrip(
            &ParseTree(Box::new(T::CastF(Box::new(F::Csv(921))))),
            "Script(OP_PUSHBYTES_2 9903 OP_NOP3)"
        );

        roundtrip(
            &ParseTree(Box::new(T::HashEqual(Sha256dHash::from_data(&[])))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL)"
        );

        roundtrip(
            &ParseTree(Box::new(T::CastE(Box::new(E::CheckMultiSig(3, keys[0..5].to_owned()))))),
            "Script(OP_PUSHNUM_3 \
                    OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                    OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                    OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 \
                    OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                    OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                    OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        roundtrip(
            &ParseTree(Box::new(T::HashEqual(Sha256dHash::from_data(&[])))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL)"
        );

        roundtrip(
            &ParseTree(Box::new(T::CastF(Box::new(F::SwitchOrV(
                Box::new(V::CheckSig(keys[0].clone())),
                Box::new(V::And(
                    Box::new(V::CheckSig(keys[1].clone())),
                    Box::new(V::CheckSig(keys[2].clone())),
                ))))),
            )),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF \
                OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIGVERIFY \
                OP_ELSE \
                OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_CHECKSIGVERIFY \
                OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_CHECKSIGVERIFY \
                OP_ENDIF OP_PUSHNUM_1)"
        );

        // fuzzer
        roundtrip(
            &ParseTree(Box::new(T::CastF(Box::new(F::SwitchOr(
                Box::new(F::Csv(9)),
                Box::new(F::Csv(7)),
            ))))),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF)"
        );

        roundtrip(
            &ParseTree(Box::new(T::And(
                Box::new(V::SwitchOrF(
                    Box::new(F::Csv(9)),
                    Box::new(F::Csv(7)),
                )),
                Box::new(T::CastF(Box::new(F::Csv(7))))
            ))),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF OP_VERIFY OP_PUSHNUM_7 OP_NOP3)"
        );

        roundtrip(
            &ParseTree(Box::new(T::CastE(Box::new(E::ParallelOr(
                Box::new(E::CheckMultiSig(0, vec![])),
                Box::new(W::CheckSig(keys[0].clone())),
            ))))),
            "Script(OP_0 OP_0 OP_CHECKMULTISIG OP_SWAP OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG OP_BOOLOR)"
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(ParseTree::parse(&script::Script::new()).is_err()); // empty script
        assert!(ParseTree::parse(&script::Script::from(vec![0])).is_err()); // FALSE and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x50])).is_err()); // TRUE and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x69])).is_err()); // VERIFY and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x10, 1])).is_err()); // incomplete push and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x03, 0x99, 0x03, 0x00, 0xb2])).is_err()); // non-minimal #
        assert!(ParseTree::parse(&script::Script::from(vec![0x85, 0x59, 0xb2])).is_err()); // leading bytes
        assert!(ParseTree::parse(&script::Script::from(vec![0x4c, 0x01, 0x69, 0xb2])).is_err()); // nonminimal push
        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x01, 0x01, 0xb2])).is_err()); // nonminimal number

        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x85])).is_err()); // OR not BOOLOR
        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x9b])).is_err()); // parallel OR without wrapping
    }
}

