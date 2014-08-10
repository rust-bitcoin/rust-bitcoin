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

//! # Script
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid
//! iff the script leaves `TRUE` on the stack after being evaluated.
//! Bitcoin's script is a stack-based assembly language similar in spirit to
//! Forth.
//!
//! This module provides the structures and functions needed to support scripts.
//!

use std::char::from_digit;
use serialize::json;

use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;

use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;

use blockdata::opcodes;
use blockdata::opcodes::Opcode;
use allops = blockdata::opcodes::all;
use blockdata::transaction::Transaction;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleDecoder, SimpleEncoder, serialize};
use util::hash::Sha256dHash;
use util::misc::find_and_remove;
use util::thinvec::ThinVec;

#[deriving(PartialEq, Show, Clone)]
/// A Bitcoin script
pub struct Script(ThinVec<u8>);

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[deriving(PartialEq, Eq, Show, Clone)]
pub enum ScriptError {
  /// OP_CHECKSIG was called with a bad public key
  BadPublicKey,
  /// An OP_ELSE happened while not in an OP_IF tree
  ElseWithoutIf,
  /// An OP_ENDIF happened while not in an OP_IF tree
  EndifWithoutIf,
  /// An OP_IF happened with an empty stack
  IfEmptyStack,
  /// An illegal opcode appeared in the script (does not need to be executed)
  IllegalOpcode,
  /// Some opcode expected a parameter, but it was missing or truncated
  EarlyEndOfScript,
  /// An OP_RETURN or synonym was executed
  ExecutedReturn,
  /// Used OP_PICK with a negative index
  NegativePick,
  /// Used OP_ROLL with a negative index
  NegativeRoll,
  /// Tried to execute a signature operation but no transaction context was provided
  NoTransaction,
  /// Tried to read an array off the stack as a number when it was more than 4 bytes
  NumericOverflow,
  /// Some stack operation was done with an empty stack
  PopEmptyStack,
  /// An OP_VERIFY happened with an empty stack
  VerifyEmptyStack,
  /// An OP_VERIFY happened with zero on the stack
  VerifyFailed,
}

/// Hashtype of a transaction, encoded in the last byte of a signature,
/// specifically in the last 5 bits `byte & 31`
#[deriving(PartialEq, Eq, Show, Clone)]
pub enum SignatureHashType {
  /// 0x1: Sign all outputs
  SigHashAll,
  /// 0x2: Sign no outputs --- anyone can choose the destination
  SigHashNone,
  /// 0x3: Sign the output whose index matches this input's index. If none exists,
  /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
  /// (This rule is probably an unintentional C++ism, but it's consensus so we have
  /// to follow it.)
  SigHashSingle,
  /// ???: Anything else is a non-canonical synonym for SigHashAll, for example
  /// zero appears a few times in the chain
  SigHashUnknown
}

impl SignatureHashType {
   /// Returns a SignatureHashType along with a boolean indicating whether
   /// the `ANYONECANPAY` flag is set, read from the last byte of a signature.
   fn from_signature(signature: &[u8]) -> (SignatureHashType, bool) {
     let byte = signature[signature.len() - 1];
     let sighash = match byte & 0x1f {
       1 => SigHashAll,
       2 => SigHashNone,
       3 => SigHashSingle,
       _ => SigHashUnknown
     };
     (sighash, (byte & 0x80) != 0)
   }
}

/// Helper to encode an integer in script format
fn build_scriptint(n: i64) -> Vec<u8> {
  let neg = n < 0;

  let mut abs = if neg { -n } else { n } as uint;
  let mut v = vec![];
  while abs > 0xFF {
    v.push((abs & 0xFF) as u8);
    abs >>= 8;
  }
  // If the number's value causes the sign bit to be set, we need an extra
  // byte to get the correct value and correct sign bit
  if abs & 0x80 != 0 {
    v.push(abs as u8);
    v.push(if neg { 0x80u8 } else { 0u8 });
  }
  // Otherwise we just set the sign bit ourselves
  else {
    abs |= if neg { 0x80 } else { 0 };
    v.push(abs as u8);
  }
  v
}

/// Helper to decode an integer in script format
/// Notice that this fails on overflow: the result is the same as in
/// bitcoind, that only 4-byte signed-magnitude values may be read as
/// numbers. They can be added or subtracted (and a long time ago,
/// multiplied and divided), and this may result in numbers which
/// can't be written out in 4 bytes or less. This is ok! The number
/// just can't be read as a number again.
/// This is a bit crazy and subtle, but it makes sense: you can load
/// 32-bit numbers and do anything with them, which back when mult/div
/// was allowed, could result in up to a 64-bit number. We don't want
/// overflow since that's suprising --- and we don't want numbers that
/// don't fit in 64 bits (for efficiency on modern processors) so we
/// simply say, anything in excess of 32 bits is no longer a number.
/// This is basically a ranged type implementation.
fn read_scriptint(v: &[u8]) -> Result<i64, ScriptError> {
  let len = v.len();
  if len == 0 { return Ok(0); }
  if len > 4 { return Err(NumericOverflow); }

  let (mut ret, sh) = v.iter()
                       .fold((0, 0), |(acc, sh), n| (acc + (*n as i64 << sh), sh + 8));
  if v[len - 1] & 0x80 != 0 {
    ret &= (1 << sh - 1) - 1;
    ret = -ret;
  }
  Ok(ret)
}

/// This is like "read_scriptint then map 0 to false and everything
/// else as true", except that the overflow rules don't apply.
#[inline]
fn read_scriptbool(v: &[u8]) -> bool {
  !v.iter().all(|&w| w == 0)
}

/// Helper to read a script uint
fn read_uint<'a, I:Iterator<(uint, &'a u8)>>(mut iter: I, size: uint)
    -> Result<uint, ScriptError> {
  let mut ret = 0;
  for _ in range(0, size) {
    match iter.next() {
      Some((_, &n)) => { ret = (ret << 8) + n as uint; }
      None => { return Err(EarlyEndOfScript); }
    }
  }
  Ok(ret)
}

// Macro to translate English stack instructions into Rust code.
// All number are references to stack positions: 1 is the top,
// 2 is the second-to-top, etc. The numbers do not change within
// an opcode; to delete the top two items do `drop 1 drop 2`
// rather than `drop 1 drop 1`, which will fail.
// This is useful for only about a dozen opcodes, but those ones
// were really hard to read and verify -- see OP_PICK and OP_ROLL
// for an example of what Rust vector-stack manipulation looks
// like.
macro_rules! stack_opcode(
  ($stack:ident($min:expr):
       $(copy $c:expr)*
       $(swap ($a:expr, $b:expr))*
       $(perm ($first:expr $(->$i:expr)*) )*
       $(drop $d:expr)*
  ) => ({
    // Record top
    let top = $stack.len();
    // Check stack size
    if top < $min { return Err(PopEmptyStack); }
    // Do copies
    $( let elem = (*$stack)[top - $c].clone();
       $stack.push(elem); )*
    // Do swaps
    $( $stack.as_mut_slice().swap(top - $a, top - $b); )*
    // Do permutations
    $( let first = $first;
       $( $stack.as_mut_slice().swap(top - first, top - $i); )* )*
    // Do drops last so that dropped values will be available above
    $( $stack.remove(top - $d); )*
  });
)

/// Macro to translate numerical operations into stack ones
macro_rules! num_opcode(
  ($stack:ident($($var:ident),*): $op:expr) => ({
    $(
      let $var = try!(read_scriptint(match $stack.pop() {
        Some(elem) => elem,
        None => { return Err(PopEmptyStack); }
      }.as_slice()));
    )*
    $stack.push(build_scriptint($op));
  });
)

/// Macro to translate hashing operations into stack ones
macro_rules! hash_opcode(
  ($stack:ident, $hash:ident) => ({
    match $stack.pop() {
      None => { return Err(PopEmptyStack); }
      Some(v) => {
        let mut engine = $hash::new();
        engine.input(v.as_slice());
        let mut ret = Vec::from_elem(engine.output_bits() / 8, 0);
        engine.result(ret.as_mut_slice());
        $stack.push(ret);
      }
    }
  });
)

// OP_VERIFY macro
macro_rules! op_verify (
  ($stack:expr) => (
    match $stack.last().map(|v| read_scriptbool(v.as_slice())) {
      None => { return Err(VerifyEmptyStack); }
      Some(false) => { return Err(VerifyFailed); }
      Some(true) => { $stack.pop(); }
    }
  )
)

impl Script {
  /// Creates a new empty script
  pub fn new() -> Script { Script(ThinVec::new()) }

  /// Adds instructions to push an integer onto the stack. Integers are
  /// encoded as little-endian signed-magnitude numbers, but there are
  /// dedicated opcodes to push some small integers.
  pub fn push_int(&mut self, data: i64) {
    // We can special-case -1, 1-16
    if data == -1 || (data >= 1 && data <=16) {
      let &Script(ref mut raw) = self;
      raw.push(data as u8 + allops::OP_TRUE as u8);
      return;
    }
    // We can also special-case zero
    if data == 0 {
      let &Script(ref mut raw) = self;
      raw.push(allops::OP_FALSE as u8);
      return;
    }
    // Otherwise encode it as data
    self.push_scriptint(data);
  }

  /// Adds instructions to push an integer onto the stack, using the explicit
  /// encoding regardless of the availability of dedicated opcodes.
  pub fn push_scriptint(&mut self, data: i64) {
    self.push_slice(build_scriptint(data).as_slice());
  }

  /// Adds instructions to push some arbitrary data onto the stack
  pub fn push_slice(&mut self, data: &[u8]) {
    let &Script(ref mut raw) = self;
    // Start with a PUSH opcode
    match data.len() {
      n if n < opcodes::OP_PUSHDATA1 as uint => { raw.push(n as u8); },
      n if n < 0x100 => {
        raw.push(opcodes::OP_PUSHDATA1 as u8);
        raw.push(n as u8);
      },
      n if n < 0x10000 => {
        raw.push(opcodes::OP_PUSHDATA2 as u8);
        raw.push((n % 0x100) as u8);
        raw.push((n / 0x100) as u8);
      },
      n if n < 0x100000000 => {
        raw.push(opcodes::OP_PUSHDATA4 as u8);
        raw.push((n % 0x100) as u8);
        raw.push(((n / 0x100) % 0x100) as u8);
        raw.push(((n / 0x10000) % 0x100) as u8);
        raw.push((n / 0x1000000) as u8);
      }
      _ => fail!("tried to put a 4bn+ sized object into a script!")
    }
    // Then push the acraw
    raw.extend(data.iter().map(|n| *n));
  }

  /// Adds an individual opcode to the script
  pub fn push_opcode(&mut self, data: allops::Opcode) {
    let &Script(ref mut raw) = self;
    raw.push(data as u8);
  }

  /// Evaluate the script, modifying the stack in place
  pub fn evaluate(&self, stack: &mut Vec<Vec<u8>>, input_context: Option<(&Transaction, uint)>)
                  -> Result<(), ScriptError> {
    let &Script(ref raw) = self;
    let secp = Secp256k1::new();

    let mut codeseparator_index = 0u;
    let mut iter = raw.iter().enumerate();
    let mut exec_stack = vec![true];
    let mut alt_stack = vec![];

    for (index, byte) in iter {
      let executing = exec_stack.iter().all(|e| *e);
println!("{}, {}   len {} stack {}", index, allops::Opcode::from_u8(*byte), stack.len(), stack);
      // The definitions of all these categories are in opcodes.rs
      match (executing, allops::Opcode::from_u8(*byte).classify()) {
        // Illegal operations mean failure regardless of execution state
        (_, opcodes::IllegalOp)       => return Err(IllegalOpcode),
        // Push number
        (true, opcodes::PushNum(n))   => stack.push(build_scriptint(n as i64)),
        // Push data
        (true, opcodes::PushBytes(n)) => stack.push(iter.by_ref().take(n).map(|(_, n)| *n).collect()),
        // Return operations mean failure, but only if executed
        (true, opcodes::ReturnOp)     => return Err(ExecutedReturn),
        // If-statements take effect when not executing
        (false, opcodes::Ordinary(opcodes::OP_IF)) => exec_stack.push(false),
        (false, opcodes::Ordinary(opcodes::OP_NOTIF)) => exec_stack.push(false),
        (false, opcodes::Ordinary(opcodes::OP_ELSE)) => {
          match exec_stack.mut_last() {
            Some(ref_e) => { *ref_e = !*ref_e }
            None => { return Err(ElseWithoutIf); }
          }
        }
        (false, opcodes::Ordinary(opcodes::OP_ENDIF)) => {
          if exec_stack.pop().is_none() {
            return Err(EndifWithoutIf);
          }
        }
        // No-ops and non-executed operations do nothing
        (true, opcodes::NoOp) | (false, _) => {}
        // Actual opcodes
        (true, opcodes::Ordinary(op)) => {
          match op {
            opcodes::OP_PUSHDATA1 => {
              let n = try!(read_uint(iter.by_ref(), 1));
              let read: Vec<u8> = iter.by_ref().take(n as uint).map(|(_, n)| *n).collect();
              if read.len() < n as uint { return Err(EarlyEndOfScript); }
              stack.push(read);
            }
            opcodes::OP_PUSHDATA2 => {
              let n = try!(read_uint(iter.by_ref(), 2));
              let read: Vec<u8> = iter.by_ref().take(n as uint).map(|(_, n)| *n).collect();
              if read.len() < n as uint { return Err(EarlyEndOfScript); }
              stack.push(read);
            }
            opcodes::OP_PUSHDATA4 => {
              let n = try!(read_uint(iter.by_ref(), 4));
              let read: Vec<u8> = iter.by_ref().take(n as uint).map(|(_, n)| *n).collect();
              if read.len() < n as uint { return Err(EarlyEndOfScript); }
              stack.push(read);
            }
            opcodes::OP_IF => {
              match stack.pop().map(|v| read_scriptbool(v.as_slice())) {
                None => { return Err(IfEmptyStack); }
                Some(b) => exec_stack.push(b)
              }
            }
            opcodes::OP_NOTIF => {
              match stack.pop().map(|v| read_scriptbool(v.as_slice())) {
                None => { return Err(IfEmptyStack); }
                Some(b) => exec_stack.push(!b),
              }
            }
            opcodes::OP_ELSE => {
              match exec_stack.mut_last() {
                Some(ref_e) => { *ref_e = !*ref_e }
                None => { return Err(ElseWithoutIf); }
              }
            }
            opcodes::OP_ENDIF => {
              if exec_stack.pop().is_none() {
                return Err(EndifWithoutIf);
              }
            }
            opcodes::OP_VERIFY => op_verify!(stack),
            opcodes::OP_TOALTSTACK => {
              match stack.pop() {
                None => { return Err(PopEmptyStack); }
                Some(elem) => { alt_stack.push(elem); }
              }
            }
            opcodes::OP_FROMALTSTACK => {
              match alt_stack.pop() {
                None => { return Err(PopEmptyStack); }
                Some(elem) => { stack.push(elem); }
              }
            }
            opcodes::OP_2DROP => stack_opcode!(stack(2): drop 1 drop 2),
            opcodes::OP_2DUP  => stack_opcode!(stack(2): copy 2 copy 1),
            opcodes::OP_3DUP  => stack_opcode!(stack(3): copy 3 copy 2 copy 1),
            opcodes::OP_2OVER => stack_opcode!(stack(4): copy 4 copy 3),
            opcodes::OP_2ROT  => stack_opcode!(stack(6): perm (1 -> 3 -> 5)
                                                         perm (2 -> 4 -> 6)),
            opcodes::OP_2SWAP => stack_opcode!(stack(4): swap (2, 4) swap (1, 3)),
            opcodes::OP_DROP  => stack_opcode!(stack(1): drop 1),
            opcodes::OP_DUP   => stack_opcode!(stack(1): copy 1),
            opcodes::OP_NIP   => stack_opcode!(stack(2): drop 2),
            opcodes::OP_OVER  => stack_opcode!(stack(2): copy 2),
            opcodes::OP_PICK => {
              let n = match stack.pop() {
                Some(data) => try!(read_scriptint(data.as_slice())),
                None => { return Err(PopEmptyStack); }
              };
              if n < 0 { return Err(NegativePick); }
              let n = n as uint;
              stack_opcode!(stack(n + 1): copy n + 1)
            }
            opcodes::OP_ROLL => {
              let n = match stack.pop() {
                Some(data) => try!(read_scriptint(data.as_slice())),
                None => { return Err(PopEmptyStack); }
              };
              if n < 0 { return Err(NegativeRoll); }
              let n = n as uint;
              stack_opcode!(stack(n + 1): copy n + 1 drop n + 1)
            }
            opcodes::OP_ROT  => stack_opcode!(stack(3): perm (1 -> 2 -> 3)),
            opcodes::OP_SWAP => stack_opcode!(stack(2): swap (1, 2)),
            opcodes::OP_TUCK => stack_opcode!(stack(2): copy 2 copy 1 drop 2),
            opcodes::OP_IFDUP => {
              match stack.last().map(|v| read_scriptbool(v.as_slice())) {
                None => { return Err(IfEmptyStack); }
                Some(false) => {}
                Some(true) => { stack_opcode!(stack(1): copy 1); }
              }
            }
            opcodes::OP_DEPTH => {
              let len = stack.len() as i64;
              stack.push(build_scriptint(len));
            }
            opcodes::OP_SIZE => {
              match stack.last().map(|v| v.len() as i64) {
                None => { return Err(IfEmptyStack); }
                Some(n) => { stack.push(build_scriptint(n)); }
              }
            }
            opcodes::OP_EQUAL | opcodes::OP_EQUALVERIFY => {
              if stack.len() < 2 { return Err(PopEmptyStack); }
              let a = stack.pop().unwrap();
              let b = stack.pop().unwrap();
println!("comparing {} to {} , eq {}", a, b, a == b)
              stack.push(build_scriptint(if a == b { 1 } else { 0 }));
              if op == opcodes::OP_EQUALVERIFY { op_verify!(stack); }
            }
            opcodes::OP_1ADD => num_opcode!(stack(a): a + 1),
            opcodes::OP_1SUB => num_opcode!(stack(a): a - 1),
            opcodes::OP_NEGATE => num_opcode!(stack(a): -a),
            opcodes::OP_ABS => num_opcode!(stack(a): a.abs()),
            opcodes::OP_NOT => num_opcode!(stack(a): if a == 0 {1} else {0}),
            opcodes::OP_0NOTEQUAL => num_opcode!(stack(a): if a != 0 {1} else {0}),
            opcodes::OP_ADD => num_opcode!(stack(b, a): a + b),
            opcodes::OP_SUB => num_opcode!(stack(b, a): a - b),
            opcodes::OP_BOOLAND => num_opcode!(stack(b, a): if a != 0 && b != 0 {1} else {0}),
            opcodes::OP_BOOLOR => num_opcode!(stack(b, a): if a != 0 || b != 0 {1} else {0}),
            opcodes::OP_NUMEQUAL => num_opcode!(stack(b, a): if a == b {1} else {0}),
            opcodes::OP_NUMNOTEQUAL => num_opcode!(stack(b, a): if a != b {1} else {0}),
            opcodes::OP_NUMEQUALVERIFY => {
              num_opcode!(stack(b, a): if a == b {1} else {0});
              op_verify!(stack);
            }
            opcodes::OP_LESSTHAN => num_opcode!(stack(b, a): if a < b {1} else {0}),
            opcodes::OP_GREATERTHAN => num_opcode!(stack(b, a): if a > b {1} else {0}),
            opcodes::OP_LESSTHANOREQUAL => num_opcode!(stack(b, a): if a <= b {1} else {0}),
            opcodes::OP_GREATERTHANOREQUAL => num_opcode!(stack(b, a): if a >= b {1} else {0}),
            opcodes::OP_MIN => num_opcode!(stack(b, a): if a < b {a} else {b}),
            opcodes::OP_MAX => num_opcode!(stack(b, a): if a > b {a} else {b}),
            opcodes::OP_WITHIN => num_opcode!(stack(c, b, a): if b <= a && a < c {1} else {0}),
            opcodes::OP_RIPEMD160 => hash_opcode!(stack, Ripemd160),
            opcodes::OP_SHA1 => hash_opcode!(stack, Sha1),
            opcodes::OP_SHA256 => hash_opcode!(stack, Sha256),
            opcodes::OP_HASH160 => {
              hash_opcode!(stack, Sha256);
              hash_opcode!(stack, Ripemd160);
            }
            opcodes::OP_HASH256 => {
              hash_opcode!(stack, Sha256);
              hash_opcode!(stack, Sha256);
            }
            opcodes::OP_CODESEPARATOR => { codeseparator_index = index; }
            opcodes::OP_CHECKSIG | opcodes::OP_CHECKSIGVERIFY => {
              if stack.len() < 2 { return Err(PopEmptyStack); }

              let pubkey = PublicKey::from_slice(stack.pop().unwrap().as_slice());
              let signature = stack.pop().unwrap();

println!("pubkey {}  sig {}", pubkey, signature);
              if pubkey.is_err() {
                stack.push(build_scriptint(0));
              } else if signature.len() == 0 {
                stack.push(build_scriptint(0));
              } else {
                // This is as far as we can go without a transaction, so fail here
                if input_context.is_none() { return Err(NoTransaction); }
                // Otherwise unwrap it
                let (tx, input_index) = input_context.unwrap();
                let pubkey = pubkey.unwrap();
                let (hashtype, anyone_can_pay) =
                    SignatureHashType::from_signature(signature.as_slice());

                // Compute the section of script that needs to be hashed: everything
                // from the last CODESEPARATOR, except the signature itself.
                let mut script = Vec::from_slice(raw.slice_from(codeseparator_index));
                find_and_remove(&mut script, signature.as_slice());

                // Compute the transaction data to be hashed
                let mut tx_copy = tx.clone();
                // Put the script into an Option so that we can move it (via take_unwrap())
                // in the following branch/loop without the move-checker complaining about
                // multiple moves.
                let mut script = Some(script);
                if anyone_can_pay {
                  // For anyone-can-pay transactions we replace the whole input array
                  // with just the current input, to ensure the others have no effect.
                  let mut old_input = tx_copy.input[input_index].clone();
                  old_input.script_sig = Script(ThinVec::from_vec(script.take_unwrap()));
                  tx_copy.input = vec![old_input];
                } else {
                  // Otherwise we keep all the inputs, blanking out the others and even
                  // resetting their sequence no. if appropriate
                  for (n, input) in tx_copy.input.mut_iter().enumerate() {
                    // Zero out the scripts of other inputs
                    if n == input_index {
                      input.script_sig = Script(ThinVec::from_vec(script.take_unwrap()));
                    } else {
                      input.script_sig = Script::new();
                      // If we aren't signing them, also zero out the sequence number
                      if hashtype == SigHashSingle || hashtype == SigHashNone {
                        input.sequence = 0;
                      }
                    }
                  }
                }

                // Erase outputs as appropriate
                let mut sighash_single_bug = false;
                match hashtype {
                  SigHashNone => { tx_copy.output = vec![]; }
                  SigHashSingle => {
                    if input_index < tx_copy.output.len() {
                      let new_outs = tx_copy.output.move_iter().take(input_index + 1).collect();
                      tx_copy.output = new_outs;
                    } else {
                      sighash_single_bug = true;
                    }
                  }
                  SigHashAll | SigHashUnknown => {}
                }

                let signature_hash = if sighash_single_bug {
                  vec![1, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0]
                } else {
                  let mut data_to_sign = serialize(&tx_copy).unwrap();
                  data_to_sign.push(*signature.last().unwrap());
                  data_to_sign.push(0);
                  data_to_sign.push(0);
                  data_to_sign.push(0);
                  serialize(&Sha256dHash::from_data(data_to_sign.as_slice())).unwrap()
                };

                match secp.verify(signature_hash.as_slice(), signature.as_slice(), &pubkey) {
                  Ok(()) => stack.push(build_scriptint(1)),
                  _ => stack.push(build_scriptint(0)),
                }
              }

              if op == opcodes::OP_CHECKSIGVERIFY { op_verify!(stack); }
            }
          }
        }
      }
    }
    Ok(())
  }
}

// User-facing serialization
impl json::ToJson for Script {
  // TODO: put this in a struct alongside an opcode decode
  fn to_json(&self) -> json::Json {
    let &Script(ref raw) = self;
    let mut ret = String::new();
    for dat in raw.iter() {
      ret.push_char(from_digit((dat / 0x10) as uint, 16).unwrap());
      ret.push_char(from_digit((dat & 0x0f) as uint, 16).unwrap());
    }
    json::String(ret)
  }
}

// Network serialization
impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for Script {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    let &Script(ref data) = self;
    data.consensus_encode(s)
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for Script {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Script, E> {
    Ok(Script(try!(ConsensusDecodable::consensus_decode(d))))
  }
}

#[cfg(test)]
mod test {
  use std::io::IoResult;

  use super::{Script, build_scriptint, read_scriptint, read_scriptbool};
  use super::{NoTransaction, PopEmptyStack, VerifyFailed};

  use network::serialize::{deserialize, serialize};
  use blockdata::opcodes;
  use blockdata::transaction::Transaction;
  use util::misc::hex_bytes;
  use util::thinvec::ThinVec;

  #[test]
  fn script() {
    let mut comp = ThinVec::new();
    let mut script = Script::new();
    assert_eq!(script, Script(ThinVec::new()));

    // small ints
    script.push_int(1);  comp.push(82u8); assert_eq!(script, Script(comp.clone()));
    script.push_int(0);  comp.push(0u8);  assert_eq!(script, Script(comp.clone()));
    script.push_int(4);  comp.push(85u8); assert_eq!(script, Script(comp.clone()));
    script.push_int(-1); comp.push(80u8); assert_eq!(script, Script(comp.clone()));
    // forced scriptint
    script.push_scriptint(4);  comp.push_all([1u8, 4]); assert_eq!(script, Script(comp.clone()));
    // big ints
    script.push_int(17); comp.push_all([1u8, 17]); assert_eq!(script, Script(comp.clone()));
    script.push_int(10000); comp.push_all([2u8, 16, 39]); assert_eq!(script, Script(comp.clone()));
    // notice the sign bit set here, hence the extra zero/128 at the end
    script.push_int(10000000); comp.push_all([4u8, 128, 150, 152, 0]); assert_eq!(script, Script(comp.clone()));
    script.push_int(-10000000); comp.push_all([4u8, 128, 150, 152, 128]); assert_eq!(script, Script(comp.clone()));

    // data
    script.push_slice("NRA4VR".as_bytes()); comp.push_all([6u8, 78, 82, 65, 52, 86, 82]); assert_eq!(script, Script(comp.clone()));

    // opcodes 
    script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
    script.push_opcode(opcodes::all::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
  }

  #[test]
  fn script_serialize() {
    let hex_script = hex_bytes("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52").unwrap();
    let script: IoResult<Script> = deserialize(hex_script.clone());
    assert!(script.is_ok());
    assert_eq!(serialize(&script.unwrap()), Ok(hex_script));
  }

  #[test]
  fn scriptint_round_trip() {
    assert_eq!(build_scriptint(-1), vec![0x81]);
    assert_eq!(build_scriptint(255), vec![255, 0]);
    assert_eq!(build_scriptint(256), vec![0, 1]);
    assert_eq!(build_scriptint(257), vec![1, 1]);
    assert_eq!(build_scriptint(511), vec![255, 1]);
    for &i in [10, 100, 255, 256, 1000, 10000, 25000, 200000, 5000000, 1000000000,
               (1 << 31) - 1, -((1 << 31) - 1)].iter() {
      assert_eq!(Ok(i), read_scriptint(build_scriptint(i).as_slice()));
      assert_eq!(Ok(-i), read_scriptint(build_scriptint(-i).as_slice()));
    }
    assert!(read_scriptint(build_scriptint(1 << 31).as_slice()).is_err());
    assert!(read_scriptint(build_scriptint(-(1 << 31)).as_slice()).is_err());
  }

  #[test]
  fn script_eval_simple() {
    let mut script = Script::new();
    assert!(script.evaluate(&mut vec![], None).is_ok());

    script.push_opcode(opcodes::all::OP_RETURN);
    assert!(script.evaluate(&mut vec![], None).is_err());
  }

  #[test]
  fn script_eval_checksig_without_tx() {
    let hex_pk = hex_bytes("1976a914e729dea4a3a81108e16376d1cc329c91db58999488ac").unwrap();
    let script_pk: Script = deserialize(hex_pk.clone()).ok().expect("scriptpk");
    // Should be able to check that the sig is there and pk correct
    // before needing a transaction
    assert_eq!(script_pk.evaluate(&mut vec![], None), Err(PopEmptyStack));
    assert_eq!(script_pk.evaluate(&mut vec![vec![], vec![]], None), Err(VerifyFailed));
    // A null signature is actually Ok -- this will just push 0 onto the stack
    // since the signature is guaranteed to fail.
    assert_eq!(script_pk.evaluate(&mut vec![vec![], hex_bytes("026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a").unwrap()], None), Ok(()));
    // But if the signature is there, we need a tx to check it
    assert_eq!(script_pk.evaluate(&mut vec![vec![0], hex_bytes("026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a").unwrap()], None), Err(NoTransaction));
  }

  #[test]
  fn script_eval_pubkeyhash() {
    // nb these are both prefixed with their length in 1 byte
    let tx_hex = hex_bytes("010000000125d6681b797691aebba34b9d8e50f769ab1e8807e78405ae505c218cf8e1e9e1a20100006a47304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c0121029fa8e8d8e3fd61183ab52f98d65500fd028a5d0a899c6bcd4ecaf1eda9eac284ffffffff0110270000000000001976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac00000000").unwrap();

    let output_hex = hex_bytes("1976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac").unwrap();

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Script = deserialize(output_hex.clone()).ok().expect("scriptpk");

    let mut stack = vec![];
    assert_eq!(tx.input[0].script_sig.evaluate(&mut stack, None), Ok(()));
    assert_eq!(script_pk.evaluate(&mut stack, Some((&tx, 0))), Ok(()));
    assert_eq!(stack.len(), 1);
    assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
println!("stack {}", stack);

  }
}


