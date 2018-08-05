
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

use secp256k1;
use util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

use blockdata::script::descriptor::{self, Descriptor};
use blockdata::script;
use blockdata::opcodes;

/// AST-related error
#[derive(Debug, Clone)]
pub enum Error {
    /// Got push when we expected opcode, or a differently sized push, or something
    UnexpectedPush(Vec<u8>),
    /// Got opcode when we expected different opcode
    UnexpectedOp(opcodes::All),
    /// Failed to parse script into instructions
    BadInstruction(script::Error),
    /// Failed to parse a push as a number
    BadNumber(script::Error),
    /// Expected a number, got a 32-byte object instead. Distinct from `BadNumber` mainly so the
    /// lexer can internally retry parsing as a hash
    WantNumberGotHash(Sha256dHash),
    /// Parsed a number out of range for what it was
    NumberOutOfRange,
    /// Parsed a number that did not round-trip
    NonMinimalNumber,
    /// Failed to parse a push as a public key
    BadPubkey(secp256k1::Error),
    /// Script started with opcode that should have been preceded by something
    UnprefixedOp(opcodes::All),
    /// Got token we were not expecting
    UnexpectedToken(Token),
    /// After parsing there was still stuff left to read
    LeadingToken(Token),
    /// Expected something, it wasn't there
    Expected(&'static str)
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::BadPubkey(e)
    }
}

/// Atom of a tokenized version of a script
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// TOALTSTACK
    ToAltStack,
    /// FROMALTSTACK
    FromAltStack,
    /// SWAP
    Swap,
    /// ADD
    Add,
    /// BOOLAND
    And,
    /// BOOLOR
    Or,
    /// IF
    If,
    /// IFDUP NOTIF
    IfDupNotIf,
    /// ELSE
    Else,
    /// ENDIF
    EndIf,
    /// VERIFY
    Verify,
    /// <n> EQUAL
    NumEqual(u32),
    /// <n> EQUALVERIFY
    NumEqualVerify(u32),
    /// <hash> SHA256 EQUAL
    HashEqual(Sha256dHash),
    /// <hash> SHA256 EQUALVERIFY
    HashEqualVerify(Sha256dHash),
    /// <pk> CHECKSIG
    CheckSig(secp256k1::PublicKey),
    /// <pk> CHECKSIGVERIFY
    CheckSigVerify(secp256k1::PublicKey),
    /// <k> <pk1> ... <pkn> <len(pk array)> CHECKMULTISIG
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    /// <k> <pk1> ... <pkn> <len(pk array)> CHECKMULTISIGVERIFY
    CheckMultiSigVerify(usize, Vec<secp256k1::PublicKey>),
    /// <n> CHECKSEQUENCEVERIFY
    Csv(u32),
}

#[derive(Debug, Clone)]
struct TokenIter(Vec<Token>);

impl TokenIter {
    fn new(mut v: Vec<Token>) -> TokenIter {
        v.reverse();
        TokenIter(v)
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    HashEqual(Sha256dHash),
    CheckSig(secp256k1::PublicKey),
    CheckMultiSig(usize, Vec<secp256k1::PublicKey>),
    ParallelAnd(Vec<Expr>),
    ParallelOr(Vec<Expr>),
    Threshold(Vec<Expr>, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Vexpr {
    HashEqualVerify(Sha256dHash),
    CheckSigVerify(secp256k1::PublicKey),
    CheckMultiSigVerify(usize, Vec<secp256k1::PublicKey>),
    Threshold(Vec<Expr>, usize),
    Wrapped(Mexpr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mexpr {
    Wrapped(Expr),
    Csv(u32),
    And(Vec<Vexpr>, Box<Mexpr>),
    SwitchOr(Box<Mexpr>, Box<Mexpr>),
    CascadeOr(Expr, Box<Mexpr>),
}

/// Trait describing the various AST components
trait AstElem: Sized {
    /// parse a sequence of tokens into the object
    fn parse(tokens: &mut TokenIter) -> Result<Self, Error>;

    /// serialize an object into a script
    fn serialize(&self, builder: script::Builder) -> script::Builder;

    /// Compile a script descriptor into this type of AST element, along with a byte-cost
    /// associated with choosing this AST element for the descriptor
    fn compile<P: descriptor::PublicKey>(descriptor: &Descriptor<P>) -> (Self, usize);
}

/// Top-level script AST type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTree(Mexpr);

impl ParseTree {
    /// Attempt to parse a script into an AST
    pub fn parse(script: &script::Script) -> Result<ParseTree, Error> {
        let tokens = reverse_lex(script)?;
        let mut iter = TokenIter::new(tokens);
        let mexpr = Mexpr::parse(&mut iter)?;
        if let Some(leading) = iter.next() {
            Err(Error::LeadingToken(leading))
        } else {
            Ok(ParseTree(mexpr))
        }
    }

    /// Serialize out an AST into a script
    pub fn serialize(&self) -> script::Script {
        Mexpr::serialize(&self.0, script::Builder::new()).into_script()
    }

    /// Compiles a descriptor into an AST tree
    pub fn compile<P: descriptor::PublicKey>(descriptor: &Descriptor<P>) -> ParseTree {
        ParseTree(Mexpr::compile(descriptor).0)
    }
}

fn lex_number(ins: Option<script::Instruction>, postfix: opcodes::All, max: Option<u32>) -> Result<u32, Error> {
    let ret = match ins {
        Some(script::Instruction::Op(op)) => {
            match op {
                opcodes::All::OP_PUSHNUM_NEG1 => Err(Error::NumberOutOfRange),
                opcodes::All::OP_PUSHBYTES_0 => Ok(0),
                opcodes::All::OP_PUSHNUM_1 => Ok(1),
                opcodes::All::OP_PUSHNUM_2 => Ok(2),
                opcodes::All::OP_PUSHNUM_3 => Ok(3),
                opcodes::All::OP_PUSHNUM_4 => Ok(4),
                opcodes::All::OP_PUSHNUM_5 => Ok(5),
                opcodes::All::OP_PUSHNUM_6 => Ok(6),
                opcodes::All::OP_PUSHNUM_7 => Ok(7),
                opcodes::All::OP_PUSHNUM_8 => Ok(8),
                opcodes::All::OP_PUSHNUM_9 => Ok(9),
                opcodes::All::OP_PUSHNUM_10 => Ok(10),
                opcodes::All::OP_PUSHNUM_11 => Ok(11),
                opcodes::All::OP_PUSHNUM_12 => Ok(12),
                opcodes::All::OP_PUSHNUM_13 => Ok(13),
                opcodes::All::OP_PUSHNUM_14 => Ok(14),
                opcodes::All::OP_PUSHNUM_15 => Ok(15),
                opcodes::All::OP_PUSHNUM_16 => Ok(16),
                x => Err(Error::UnexpectedOp(x)),
            }
        }
        Some(script::Instruction::PushBytes(bytes)) if bytes.len() == 32 => {
            Err(Error::WantNumberGotHash(Sha256dHash::from(bytes)))
        }
        Some(script::Instruction::PushBytes(bytes)) => {
            match script::read_scriptint(bytes) {
                Ok(v) if v >= 0 => {
                    if &script::Builder::new().push_int(v).into_script()[1..] != bytes {
                        return Err(Error::NonMinimalNumber);
                    }
                    Ok(v as u32)
                }
                Ok(_) => return Err(Error::NumberOutOfRange),
                Err(e) => return Err(Error::BadNumber(e)),
            }
        }
        Some(script::Instruction::Error(e)) => Err(Error::BadInstruction(e)),
        None => Err(Error::UnprefixedOp(postfix)),
    };

    if let (&Ok(n), &Some(max)) = (&ret, &max) {
        if n > max {
            return Err(Error::NumberOutOfRange);
        }
    }
    ret
}

/// Tokenize a script, in reverse order. The reversal is because our parser works best
/// backward, and also the lexer has an easier time tokenizing backward (once we've
/// turned the script into a series of ops and pushes)
pub fn reverse_lex(script: &script::Script) -> Result<Vec<Token>, Error> {
    let instructions: Vec<script::Instruction> = {
        let mut vec = Vec::with_capacity(script.len());
        for ins in script.into_iter() {
            if let script::Instruction::Error(e) = ins {
                return Err(Error::BadInstruction(e));
            }
            vec.push(ins);
        }
        vec
    };
    let mut ret = Vec::with_capacity(instructions.len());
    let secp = secp256k1::Secp256k1::with_caps(secp256k1::ContextFlag::None);

    let mut iter = instructions.into_iter().rev();
    while let Some(ins) = iter.next() {
        match ins {
            script::Instruction::Error(_) => unreachable!(),
            script::Instruction::PushBytes(bytes) => return Err(Error::UnexpectedPush(bytes.to_owned())),
            script::Instruction::Op(opcodes::All::OP_TOALTSTACK) => ret.push(Token::ToAltStack),
            script::Instruction::Op(opcodes::All::OP_FROMALTSTACK) => ret.push(Token::FromAltStack),
            script::Instruction::Op(opcodes::All::OP_SWAP) => ret.push(Token::Swap),
            script::Instruction::Op(opcodes::All::OP_ADD) => ret.push(Token::Add),
            script::Instruction::Op(opcodes::All::OP_BOOLAND) => ret.push(Token::And),
            script::Instruction::Op(opcodes::All::OP_BOOLOR) => ret.push(Token::Or),
            script::Instruction::Op(opcodes::All::OP_IF) => ret.push(Token::If),
            script::Instruction::Op(opcodes::All::OP_ELSE) => ret.push(Token::Else),
            script::Instruction::Op(opcodes::All::OP_ENDIF) => ret.push(Token::EndIf),
            script::Instruction::Op(opcodes::All::OP_VERIFY) => ret.push(Token::Verify),

            script::Instruction::Op(opcodes::All::OP_NOTIF) => {
                match iter.next() {
                    Some(script::Instruction::Op(opcodes::All::OP_IFDUP)) => ret.push(Token::IfDupNotIf),
                    Some(script::Instruction::Op(op)) => return Err(Error::UnexpectedOp(op)),
                    Some(script::Instruction::PushBytes(bytes)) => return Err(Error::UnexpectedPush(bytes.to_owned())),
                    Some(script::Instruction::Error(e)) => return Err(Error::BadInstruction(e)),
                    None => return Err(Error::UnprefixedOp(opcodes::All::OP_NOTIF)),
                }
            }

            script::Instruction::Op(opcodes::All::OP_EQUAL) => {
                match lex_number(iter.next(), opcodes::All::OP_EQUAL, None) {
                    Ok(n) => ret.push(Token::NumEqual(n)),
                    Err(Error::WantNumberGotHash(hash)) => {
                        match iter.next() {
                            Some(script::Instruction::Op(opcodes::All::OP_SHA256)) => ret.push(Token::HashEqual(hash)),
                            _ => return Err(Error::Expected("OP_SHA256")),
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
            script::Instruction::Op(opcodes::All::OP_EQUALVERIFY) => {
                match lex_number(iter.next(), opcodes::All::OP_EQUALVERIFY, None) {
                    Ok(n) => ret.push(Token::NumEqualVerify(n)),
                    Err(Error::WantNumberGotHash(hash)) => {
                        match iter.next() {
                            Some(script::Instruction::Op(opcodes::All::OP_SHA256)) => ret.push(Token::HashEqualVerify(hash)),
                            _ => return Err(Error::Expected("OP_SHA256")),
                        }
                    },
                    Err(e) => return Err(e),
                }
            }

            script::Instruction::Op(op @ opcodes::All::OP_CHECKSIG) |
            script::Instruction::Op(op @ opcodes::All::OP_CHECKSIGVERIFY) => {
                match iter.next() {
                    Some(script::Instruction::PushBytes(bytes)) => {
                        if op == opcodes::All::OP_CHECKSIG {
                            ret.push(Token::CheckSig(secp256k1::PublicKey::from_slice(&secp, bytes)?));
                        } else {
                            ret.push(Token::CheckSigVerify(secp256k1::PublicKey::from_slice(&secp, bytes)?));
                        }
                    }
                    Some(script::Instruction::Op(op)) => return Err(Error::UnexpectedOp(op)),
                    Some(script::Instruction::Error(e)) => return Err(Error::BadInstruction(e)),
                    None => return Err(Error::UnprefixedOp(op))
                }
            }

            script::Instruction::Op(op @ opcodes::All::OP_CHECKMULTISIG) |
            script::Instruction::Op(op @ opcodes::All::OP_CHECKMULTISIGVERIFY) => {
                let m = lex_number(iter.next(), op, Some(20))?;
                let mut key_vec = Vec::with_capacity(m as usize);
                for _ in 0..m {
                    match iter.next() {
                        Some(script::Instruction::PushBytes(bytes)) => {
                            key_vec.push(secp256k1::PublicKey::from_slice(&secp, bytes)?);
                        }
                        Some(script::Instruction::Op(op)) => return Err(Error::UnexpectedOp(op)),
                        Some(script::Instruction::Error(e)) => return Err(Error::BadInstruction(e)),
                        None => return Err(Error::UnprefixedOp(op)),
                    }
                }
                key_vec.reverse();
                let n = lex_number(iter.next(), op, Some(m))?;
                if op == opcodes::All::OP_CHECKMULTISIG {
                    ret.push(Token::CheckMultiSig(n as usize, key_vec));
                } else {
                    ret.push(Token::CheckMultiSigVerify(n as usize, key_vec));
                }
            }

            script::Instruction::Op(op) if op == opcodes::OP_CSV => {
                ret.push(Token::Csv(lex_number(iter.next(), opcodes::OP_CSV, None)?));
            }

            script::Instruction::Op(op) => return Err(Error::UnexpectedOp(op)),
        }
    }
    Ok(ret)
}

impl AstElem for Mexpr {
    fn parse(tokens: &mut TokenIter) -> Result<Mexpr, Error> {
        let mexpr = match tokens.next() {
            Some(Token::Csv(n)) => Mexpr::Csv(n),
            Some(Token::EndIf) => {
                let or_right = Mexpr::parse(tokens)?;
                match tokens.next() {
                    Some(Token::Else) => {
                        let or_left = Mexpr::parse(tokens)?;
                        match tokens.next() {
                            Some(Token::If) => {}
                            _ => return Err(Error::Expected("OP_IF"))
                        }
                        Mexpr::SwitchOr(Box::new(or_left), Box::new(or_right))
                    }
                    Some(Token::IfDupNotIf) => {
                        let or_left = Expr::parse(tokens)?;
                        Mexpr::CascadeOr(or_left, Box::new(or_right))
                    }
                    _ => return Err(Error::Expected("OP_ELSE or OP_NOTIF"))
                }
            }
            Some(x) => {
                tokens.un_next(x);
                Expr::parse(tokens).map(Mexpr::Wrapped)?
            }
            None => return Err(Error::Expected("expression"))
        };

        let mut and_vexprs = vec![];
        while let Some(more) = tokens.next() {
            tokens.un_next(more);
            match Vexpr::parse(tokens) {
                Ok(vexpr) => and_vexprs.push(vexpr),
                Err(Error::UnexpectedToken(t)) => {
                    tokens.un_next(t);
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        if and_vexprs.is_empty() {
            Ok(mexpr)
        } else {
            and_vexprs.reverse();
            Ok(Mexpr::And(and_vexprs, Box::new(mexpr)))
        }
    }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            Mexpr::Wrapped(ref expr) => Expr::serialize(expr, builder),
            Mexpr::Csv(n) => builder.push_int(n as i64)
                                    .push_opcode(opcodes::OP_CSV),
            Mexpr::And(ref vexpr, ref mexpr) => {
                for v in vexpr {
                    builder = Vexpr::serialize(v, builder);
                }
                Mexpr::serialize(mexpr, builder)
            }
            Mexpr::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::All::OP_IF);
                builder = Mexpr::serialize(left, builder);
                builder = builder.push_opcode(opcodes::All::OP_ELSE);
                builder = Mexpr::serialize(right, builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
            Mexpr::CascadeOr(ref left, ref right) => {
                builder = Expr::serialize(left, builder);
                builder = builder.push_opcode(opcodes::All::OP_IFDUP)
                                 .push_opcode(opcodes::All::OP_NOTIF);
                builder = Mexpr::serialize(right, builder);
                builder.push_opcode(opcodes::All::OP_ENDIF)
            }
        }
    }

    fn compile<P: descriptor::PublicKey>(descriptor: &Descriptor<P>) -> (Mexpr, usize) {
        match *descriptor {
            Descriptor::Key(ref key) => (Mexpr::Wrapped(Expr::CheckSig(key.as_pubkey())), 35),
            Descriptor::Hash(hash) => (Mexpr::Wrapped(Expr::HashEqual(hash)), 35),
            Descriptor::Csv(n) => (Mexpr::Csv(n), 6),
            Descriptor::And(ref subs) => {
                // Determine which sub-descriptor we save the most bytes on by moving it to
                // the last in line.
                let (min_mexpr_idx, _) = subs
                    .iter()
                    .enumerate()
                    .rev()  // reverse the list so `min_by_key` will prefer the currently last element
                    .min_by_key(|(_, x)| Mexpr::compile(x).1 as isize - Vexpr::compile(x).1 as isize)
                    .expect("nonempty and clause");

                let mut cost = 0;
                let mut vexprs = Vec::with_capacity(subs.len() - 1);
                for (n, sub) in subs.iter().enumerate() {
                    if n != min_mexpr_idx {
                        let (vexpr, c) = Vexpr::compile(sub);
                        vexprs.push(vexpr);
                        cost += c + 1;
                    }
                }
                let (mexpr, c) = Mexpr::compile(&subs[min_mexpr_idx]);
                (Mexpr::And(vexprs, Box::new(mexpr)), cost + c)
            }
            Descriptor::AsymmetricOr(ref a, ref b) => {
                let (expr_a, cost_a) = Expr::compile(a);
                let (mexpr_b, cost_b) = Mexpr::compile(b);
                // TODO check cost of expr_a
                (Mexpr::CascadeOr(expr_a, Box::new(mexpr_b)), 3 + cost_a + cost_b)
            }
            Descriptor::Or(_, _) => unimplemented!(),
            Descriptor::Threshold(_, ref subs) => {
                let is_expr = subs.iter().all(|x|
                    match *x {
                        Descriptor::Key(_) => true,
                        _ => false,
                    }
                );
                if is_expr {
                    let (expr, cost) = Expr::compile(descriptor);
                    (Mexpr::Wrapped(expr), cost)
                } else {
                    unimplemented!()
                }
            }
        }
    }
}

impl AstElem for Vexpr {
    fn parse(tokens: &mut TokenIter) -> Result<Vexpr, Error> {
        match tokens.next() {
            Some(Token::CheckSigVerify(pk)) => Ok(Vexpr::CheckSigVerify(pk)),
            Some(Token::CheckMultiSigVerify(k, pks)) => Ok(Vexpr::CheckMultiSigVerify(k, pks)),
            Some(Token::HashEqualVerify(hash)) => Ok(Vexpr::HashEqualVerify(hash)),
            Some(Token::Verify) => Mexpr::parse(tokens).map(Vexpr::Wrapped),
            Some(Token::NumEqualVerify(n)) => Ok(Vexpr::Threshold(parse_wexprs(tokens, Token::Add)?, n as usize)),
            Some(x) => Err(Error::UnexpectedToken(x)),
            None => Err(Error::Expected("OP_CHECKSIGVERIFY or OP_CHECKMULTISIGVERIFY or OP_EQUALVERIFY or OP_VERIFY"))
        }
    }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            Vexpr::HashEqualVerify(hash) => {
                builder.push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUALVERIFY)
            }
            Vexpr::CheckSigVerify(ref pk) => {
                builder.push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIGVERIFY)
            }
            Vexpr::CheckMultiSigVerify(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
            }
            Vexpr::Threshold(ref exprs, k) => {
                serialize_wexprs(exprs, builder, opcodes::All::OP_ADD).push_int(k as i64)
                                                                      .push_opcode(opcodes::All::OP_EQUALVERIFY)
            }
            Vexpr::Wrapped(ref mexpr) => Mexpr::serialize(mexpr, builder).push_opcode(opcodes::All::OP_VERIFY),
        }
    }

    fn compile<P: descriptor::PublicKey>(descriptor: &Descriptor<P>) -> (Vexpr, usize) {
        match *descriptor {
            Descriptor::Key(ref key) => (Vexpr::CheckSigVerify(key.as_pubkey()), 35),
            Descriptor::Hash(hash) => (Vexpr::HashEqualVerify(hash), 35),
            Descriptor::Csv(n) => (Vexpr::Wrapped(Mexpr::Csv(n)), 7),
            Descriptor::And(_) => unimplemented!(),
            Descriptor::Or(_, _) => unimplemented!(),
            Descriptor::AsymmetricOr(_, _) => unimplemented!(),
            Descriptor::Threshold(k, ref subs) => {
                let all_keys = subs.iter().all(|x| if let Descriptor::Key(_) = *x { true } else { false });

                if all_keys && subs.len() <= 20 {
                    let mut keys = Vec::with_capacity(subs.len());
                    for sub in subs {
                        match *sub {
                            Descriptor::Key(ref key) => keys.push(key.as_pubkey()),
                            _ => unreachable!(),
                        }
                    }

                    let len = 3 + 34 * keys.len() + match (k > 16, subs.len() > 16) {
                        (true, true) => 2,
                        (false, true) => 1,
                        (true, false) => 1,
                        (false, false) => 0,
                    };
                    (Vexpr::CheckMultiSigVerify(k, keys), len)
                } else {
                    unimplemented!()
                }
            }
        }
    }
}

impl AstElem for Expr {
    fn parse(tokens: &mut TokenIter) -> Result<Expr, Error> {
        match tokens.next() {
            Some(Token::CheckSig(pk)) => Ok(Expr::CheckSig(pk)),
            Some(Token::HashEqual(hash)) => Ok(Expr::HashEqual(hash)),
            Some(Token::CheckMultiSig(k, pks)) => Ok(Expr::CheckMultiSig(k, pks)),
            Some(Token::And) => {
                tokens.un_next(Token::And);
                Ok(Expr::ParallelAnd(parse_wexprs(tokens, Token::And)?))
            },
            Some(Token::Or) => {
                tokens.un_next(Token::Or);
                Ok(Expr::ParallelOr(parse_wexprs(tokens, Token::Or)?))
            },
            Some(Token::NumEqual(n)) => Ok(Expr::Threshold(parse_wexprs(tokens, Token::Add)?, n as usize)),
            _ => return Err(Error::Expected("OP_CHECKSIG or OP_CHECKMULTISIG or OP_EQUAL or OP_BOOLOR or wexpr"))
        }
    }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            Expr::HashEqual(hash) => {
                builder.push_opcode(opcodes::All::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::All::OP_EQUAL)
            }
            Expr::CheckSig(ref pk) => {
                builder.push_slice(&pk.serialize()[..])
                       .push_opcode(opcodes::All::OP_CHECKSIG)
            }
            Expr::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_slice(&pk.serialize()[..]);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::All::OP_CHECKMULTISIG)
            }
            Expr::ParallelAnd(ref exprs) => serialize_wexprs(exprs, builder, opcodes::All::OP_BOOLAND),
            Expr::ParallelOr(ref exprs) => serialize_wexprs(exprs, builder, opcodes::All::OP_BOOLOR),
            Expr::Threshold(ref exprs, k) => {
                serialize_wexprs(exprs, builder, opcodes::All::OP_ADD).push_int(k as i64)
                                                                      .push_opcode(opcodes::All::OP_EQUAL)
            }
        }
    }

    fn compile<P: descriptor::PublicKey>(descriptor: &Descriptor<P>) -> (Expr, usize) {
        match *descriptor {
            Descriptor::Key(ref key) => (Expr::CheckSig(key.as_pubkey()), 35),
            Descriptor::Hash(hash) => (Expr::HashEqual(hash), 35),

            Descriptor::Csv(_) => unimplemented!(),
            Descriptor::And(_) => unimplemented!(),
            Descriptor::Or(_, _) => unimplemented!(),
            Descriptor::AsymmetricOr(_, _) => unimplemented!(),
            Descriptor::Threshold(k, ref subs) => {
                let all_keys = subs.iter().all(|x| if let Descriptor::Key(_) = *x { true } else { false });

                if all_keys && subs.len() <= 20 {
                    let mut keys = Vec::with_capacity(subs.len());
                    for sub in subs {
                        match *sub {
                            Descriptor::Key(ref key) => keys.push(key.as_pubkey()),
                            _ => unreachable!(),
                        }
                    }

                    let len = 3 + 34 * keys.len() + match (k > 16, subs.len() > 16) {
                        (true, true) => 2,
                        (false, true) => 1,
                        (true, false) => 1,
                        (false, false) => 0,
                    };
                    (Expr::CheckMultiSig(k, keys), len)
                } else {
                    unimplemented!()
                }
            }
        }
    }
}

fn parse_wexprs(tokens: &mut TokenIter, sep: Token) -> Result<Vec<Expr>, Error> {
    let mut ret = vec![];

    loop {
        if let Some(tok) = tokens.next() {
            if tok != sep {
                tokens.un_next(tok);
                break;
            }
        }

        let (expr, expect_swap) = match tokens.next() {
            Some(Token::CheckSig(pk)) => (Expr::CheckSig(pk), true),
            Some(Token::HashEqual(hash)) => (Expr::HashEqual(hash), true),
            Some(Token::FromAltStack) => {
                let expr = Expr::parse(tokens)?;
                match tokens.next() {
                    Some(Token::ToAltStack) => (expr, false),
                    _ => return Err(Error::Expected("OP_TOALTSTACK")),
                }
            }
            _ => return Err(Error::Expected("expression or wrapped expression")),
        };
        ret.push(expr);

        if expect_swap {
            match tokens.next() {
                Some(Token::Swap) => {},
                _ => return Err(Error::Expected("OP_SWAP"))
            }
        }
    }
    ret.push(Expr::parse(tokens)?);

    ret.reverse();
    Ok(ret)
}

fn serialize_wexprs(wexpr: &[Expr], mut builder: script::Builder, sep: opcodes::All) -> script::Builder {
    if !wexpr.is_empty() {
        builder = Expr::serialize(&wexpr[0], builder);
        for expr in &wexpr[1..] {
            builder = match *expr {
                Expr::CheckSig(_) | Expr::HashEqual(_) => {
                    builder = builder.push_opcode(opcodes::All::OP_SWAP);
                    Expr::serialize(expr, builder)
                }
                _ => {
                    builder = builder.push_opcode(opcodes::All::OP_TOALTSTACK);
                    builder = Expr::serialize(expr, builder);
                    builder.push_opcode(opcodes::All::OP_FROMALTSTACK)
                }
            }.push_opcode(sep);
        }
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

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
            &ParseTree(Mexpr::Wrapped(Expr::CheckSig(keys[0].clone()))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &ParseTree(Mexpr::Wrapped(Expr::CheckMultiSig(3, keys.clone()))),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        // Liquid policy
        roundtrip(
            &ParseTree(Mexpr::CascadeOr(
                Expr::CheckMultiSig(2, keys[0..2].to_owned()),
                Box::new(Mexpr::And(
                     vec![Vexpr::CheckMultiSigVerify(2, keys[3..5].to_owned())],
                     Box::new(Mexpr::Csv(10000)),
                 )),
             )),
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
            &ParseTree(Mexpr::Csv(921)),
            "Script(OP_PUSHBYTES_2 9903 OP_NOP3)"
        );

        roundtrip(
            &ParseTree(Mexpr::Wrapped(Expr::Threshold(vec![Expr::CheckSig(keys[0].clone())], 1))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG \
                    OP_PUSHNUM_1 OP_EQUAL)"
        );

        roundtrip(
            &ParseTree(Mexpr::Wrapped(Expr::Threshold(vec![
                Expr::CheckSig(keys[0].clone()),
                Expr::CheckSig(keys[1].clone()),
                Expr::CheckSig(keys[2].clone()),
                Expr::CheckSig(keys[3].clone()),
                Expr::CheckSig(keys[4].clone()),
            ], 3))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG \
                    OP_SWAP OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_CHECKSIG OP_ADD \
                    OP_SWAP OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_CHECKSIG OP_ADD \
                    OP_SWAP OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_CHECKSIG OP_ADD \
                    OP_SWAP OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_CHECKSIG OP_ADD \
                    OP_PUSHNUM_3 OP_EQUAL)"
        );

        // Check ordering of Mexpr::And vector (caught by fuzzing)
        roundtrip(
            &ParseTree(Mexpr::And(
                vec![
                    Vexpr::CheckMultiSigVerify(0, vec![]),
                    Vexpr::Threshold(vec![
                        Expr::CheckMultiSig(0, vec![])
                    ], 0),
                ],
                Box::new(Mexpr::Csv(0))
            )),
            "Script(OP_0 OP_0 OP_CHECKMULTISIGVERIFY OP_0 OP_0 OP_CHECKMULTISIG OP_0 OP_EQUALVERIFY OP_0 OP_NOP3)"
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

