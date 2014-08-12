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
use std::default::Default;
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
  /// OP_CHECKSIG was called with a bad signature
  BadSignature,
  /// An ECDSA error
  EcdsaError(::secp256k1::Error),
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
  /// A multisig tx with negative or too many keys
  MultisigBadKeyCount(int),
  /// A multisig tx with negative or too many signatures
  MultisigBadSigCount(int),
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
  if n == 0 { return vec![] }

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
pub fn read_scriptint(v: &[u8]) -> Result<i64, ScriptError> {
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
pub fn read_scriptbool(v: &[u8]) -> bool {
  !v.iter().all(|&w| w == 0)
}

/// Read a script-encoded unsigned integer
pub fn read_uint<'a, I:Iterator<(uint, &'a u8)>>(mut iter: I, size: uint)
    -> Result<uint, ScriptError> {
  let mut ret = 0;
  for i in range(0, size) {
    match iter.next() {
      Some((_, &n)) => ret += n as uint << (i * 8),
      None => { return Err(EarlyEndOfScript); }
    }
  }
  Ok(ret)
}

/// Check a signature -- returns an error that is currently just translated
/// into a 0/1 to push onto the script stack
fn check_signature(secp: &Secp256k1, sig_slice: &[u8], pk_slice: &[u8], script: Vec<u8>,
                   tx: &Transaction, input_index: uint) -> Result<(), ScriptError> {

  // Check public key
  let pubkey = PublicKey::from_slice(pk_slice);
  if pubkey.is_err() {
    return Err(BadPublicKey);
  }
  let pubkey = pubkey.unwrap();

  // Check signature and hashtype
  if sig_slice.len() == 0 {
    return Err(BadSignature);
  }
  let (hashtype, anyone_can_pay) = SignatureHashType::from_signature(sig_slice);

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
        let mut new_outs = Vec::with_capacity(input_index + 1);
        for _ in range(0, input_index) {
          new_outs.push(Default::default())
        }
        new_outs.push(tx_copy.output.swap_remove(input_index).unwrap());
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
    data_to_sign.push(*sig_slice.last().unwrap());
    data_to_sign.push(0);
    data_to_sign.push(0);
    data_to_sign.push(0);
    serialize(&Sha256dHash::from_data(data_to_sign.as_slice())).unwrap()
  };

  secp.verify(signature_hash.as_slice(), sig_slice, &pubkey).map_err(|e| EcdsaError(e))
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
      // The definitions of all these categories are in opcodes.rs
//println!("read {} as {}", allops::Opcode::from_u8(*byte), allops::Opcode::from_u8(*byte).classify());
      match (executing, allops::Opcode::from_u8(*byte).classify()) {
        // Illegal operations mean failure regardless of execution state
        (_, opcodes::IllegalOp)       => return Err(IllegalOpcode),
        // Push number
        (true, opcodes::PushNum(n))   => stack.push(build_scriptint(n as i64)),
        // Push data
        (true, opcodes::PushBytes(n)) => stack.push(iter.by_ref().take(n).map(|(_, n)| *n).collect()),
        // Return operations mean failure, but only if executed
        (true, opcodes::ReturnOp)     => return Err(ExecutedReturn),
        // Data-reading statements still need to read, even when not executing
        (false, opcodes::PushBytes(n)) => { for _ in range(0, n) { iter.next(); } }
        (false, opcodes::Ordinary(opcodes::OP_PUSHDATA1)) => {
          let n = try!(read_uint(iter.by_ref(), 1));
          for _ in range(0, n) { iter.next(); }
        }
        (false, opcodes::Ordinary(opcodes::OP_PUSHDATA2)) => {
          let n = try!(read_uint(iter.by_ref(), 2));
          for _ in range(0, n) { iter.next(); }
        }
        (false, opcodes::Ordinary(opcodes::OP_PUSHDATA4)) => {
          let n = try!(read_uint(iter.by_ref(), 4));
          for _ in range(0, n) { iter.next(); }
        }
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

              let pk = stack.pop().unwrap();
              let pk_slice = pk.as_slice();
              let sig = stack.pop().unwrap();
              let sig_slice = sig.as_slice();

              // Compute the section of script that needs to be hashed: everything
              // from the last CODESEPARATOR, except the signature itself.
              let mut script = Vec::from_slice(raw.slice_from(codeseparator_index));
              find_and_remove(&mut script, sig_slice);

              // This is as far as we can go without a transaction, so fail here
              if input_context.is_none() { return Err(NoTransaction); }
              // Otherwise unwrap it
              let (tx, input_index) = input_context.unwrap();

              match check_signature(&secp, sig_slice, pk_slice, script, tx, input_index) {
                Ok(()) => stack.push(build_scriptint(1)),
                _ => stack.push(build_scriptint(0)),
              }
              if op == opcodes::OP_CHECKSIGVERIFY { op_verify!(stack); }
            }
            opcodes::OP_CHECKMULTISIG | opcodes::OP_CHECKMULTISIGVERIFY => {
              // Read all the keys
              if stack.len() < 1 { return Err(PopEmptyStack); }
              let n_keys = try!(read_scriptint(stack.pop().unwrap().as_slice()));
              if n_keys < 0 || n_keys > 20 {
                return Err(MultisigBadKeyCount(n_keys as int));
              }

              if (stack.len() as i64) < n_keys { return Err(PopEmptyStack); }
              let mut keys = Vec::with_capacity(n_keys as uint);
              for _ in range(0, n_keys) {
                keys.push(stack.pop().unwrap());
              }

              // Read all the signatures
              if stack.len() < 1 { return Err(PopEmptyStack); }
              let n_sigs = try!(read_scriptint(stack.pop().unwrap().as_slice()));
              if n_sigs < 0 || n_sigs > n_keys {
                return Err(MultisigBadSigCount(n_sigs as int));
              }

              if (stack.len() as i64) < n_sigs { return Err(PopEmptyStack); }
              let mut sigs = Vec::with_capacity(n_sigs as uint);
              for _ in range(0, n_sigs) {
                sigs.push(stack.pop().unwrap());
              }

              // Pop one more element off the stack to be replicate a consensus bug
              if stack.pop().is_none() { return Err(PopEmptyStack); }

              // Compute the section of script that needs to be hashed: everything
              // from the last CODESEPARATOR, except the signatures themselves.
              let mut script = Vec::from_slice(raw.slice_from(codeseparator_index));
              for sig in sigs.iter() {
                find_and_remove(&mut script, sig.as_slice());
              }

              // This is as far as we can go without a transaction, so fail here
              if input_context.is_none() { return Err(NoTransaction); }
              // Otherwise unwrap it
              let (tx, input_index) = input_context.unwrap();

              // Check signatures
              let mut key_iter = keys.iter();
              let mut sig_iter = sigs.iter();
              let mut key = key_iter.next();
              let mut sig = sig_iter.next();
              loop {
//println!("key({}) {}  sig({}) {}", key.map(|k| k.len()), key, sig.map(|s| s.len()), sig);
                match (key, sig) {
                  // Try to validate the signature with the given key
                  (Some(k), Some(s)) => {
                    // Move to the next signature if it is valid for the current key
                    if check_signature(&secp, s.as_slice(), k.as_slice(),
                                       script.clone(), tx, input_index).is_ok() {
                      sig = sig_iter.next();
                    }
                    // Move to the next key in any case
                    key = key_iter.next();
                  }
                  // Run out of signatures, success
                  (_, None) => {
                    stack.push(build_scriptint(1));
                    break;
                  }
                  // Run out of keys to match to signatures, fail
                  (None, Some(_)) => {
                    stack.push(build_scriptint(0));
                    break;
                  }
                }
              }
              if op == opcodes::OP_CHECKMULTISIGVERIFY { op_verify!(stack); }
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
  use serialize::hex::FromHex;

  use super::{Script, build_scriptint, read_scriptint, read_scriptbool};
  use super::{NoTransaction, PopEmptyStack, VerifyFailed};

  use network::serialize::{deserialize, serialize};
  use blockdata::opcodes;
  use blockdata::transaction::Transaction;
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
    let hex_script = "6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52".from_hex().unwrap();
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
    let hex_pk = "1976a914e729dea4a3a81108e16376d1cc329c91db58999488ac".from_hex().unwrap();
    let script_pk: Script = deserialize(hex_pk.clone()).ok().expect("scriptpk");
    // Should be able to check that the sig is there and pk correct
    // before needing a transaction
    assert_eq!(script_pk.evaluate(&mut vec![], None), Err(PopEmptyStack));
    assert_eq!(script_pk.evaluate(&mut vec![vec![], vec![]], None), Err(VerifyFailed));
    // But if the signature is there, we need a tx to check it
    assert_eq!(script_pk.evaluate(&mut vec![vec![], "026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a".from_hex().unwrap()], None), Err(NoTransaction));
    assert_eq!(script_pk.evaluate(&mut vec![vec![0], "026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a".from_hex().unwrap()], None), Err(NoTransaction));
  }

  #[test]
  fn script_eval_pubkeyhash() {
    // nb these are both prefixed with their length in 1 byte
    let tx_hex = "010000000125d6681b797691aebba34b9d8e50f769ab1e8807e78405ae505c218cf8e1e9e1a20100006a47304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c0121029fa8e8d8e3fd61183ab52f98d65500fd028a5d0a899c6bcd4ecaf1eda9eac284ffffffff0110270000000000001976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac00000000".from_hex().unwrap();

    let output_hex = "1976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac".from_hex().unwrap();

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Script = deserialize(output_hex.clone()).ok().expect("scriptpk");

    let mut stack = vec![];
    assert_eq!(tx.input[0].script_sig.evaluate(&mut stack, None), Ok(()));
    assert_eq!(script_pk.evaluate(&mut stack, Some((&tx, 0))), Ok(()));
    assert_eq!(stack.len(), 1);
    assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
  }


  #[test]
  fn script_eval_testnet_failure_1() {
    // OP_PUSHNUM ops weren't correct, also computed zero must be [], not [0]
    // txid dc3aad51b4b9ea1ef40755a38b0b4d6e08c72d2ac5e95b8bebe9bd319b6aed7e
    let tx_hex = "010000000560e0b5061b08a60911c9b2702cc0eba80adbe42f3ec9885c76930837db5380c001000000054f01e40164ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b959000000000351519bffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b959020000000452018293ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b95903000000045b5a5193ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b95904000000045b5a5193ffffffff06002d310100000000029f91002d3101000000000401908f87002d31010000000001a0002d3101000000000705feffffff808730d39700000000001976a9140467f85e06a2ef0a479333b47258f4196fb94b2c88ac002d3101000000000604ffffff7f9c00000000".from_hex().unwrap();

    let output_hex = vec![ vec![1, 0xa5], vec![1, 0x61], vec![2, 0x00, 0x87], vec![1, 0x9c], vec![2, 0x9d, 0x51] ];

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Vec<Script> = output_hex.iter().map(|hex| deserialize(hex.clone()).ok().expect("scriptpk")).collect();

    for (n, script) in script_pk.iter().enumerate() {
      let mut stack = vec![];
      assert_eq!(tx.input[n].script_sig.evaluate(&mut stack, None), Ok(()));
      assert_eq!(script.evaluate(&mut stack, Some((&tx, n))), Ok(()));
      assert!(stack.len() >= 1);
      assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
    }
  }

  #[test]
  fn script_eval_testnet_failure_2() {
    // OP_PUSHDATA2 must read its length little-endian
    // txid c5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7)
    let tx_hex = "010000003422300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560300000006011601150114ffffffff22300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560400000006011601150114ffffffff22300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560900000006050000008000ffffffff42e9e966f8c293ad44c0b726ec85c5338d1f30cee63aedfb6ead49571477f22909000000020051ffffffff42e9e966f8c293ad44c0b726ec85c5338d1f30cee63aedfb6ead49571477f2290a000000034f00a3ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f030000000151ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f040000000451525355ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f0500000003016f8cffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f09000000025d5effffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a0400000005016f5a5193ffffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a06000000065a005b6b756cffffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a080000000100ffffffff67e36cd8a0a57458261704363fc21ce927b8214b381bcf86c0b6bd8f23e5e70c0100000006011601150114ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d6537040000000704ffffff7f7693ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d6537050000001b1a6162636465666768696a6b6c6d6e6f707172737475767778797affffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d653708000000044d010008ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d65370a000000025191ffffffff6f3c0204703766775324115c32fd121a16f0df64f0336490157ebd94b62e059e02000000020075ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e0295020100000006016f51935c94ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e029502020000000403008000ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e029502060000001b1a6162636465666768696a6b6c6d6e6f707172737475767778797affffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e02950207000000044f005152ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e0295020a00000003515193ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a330300000000025100ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a33030500000006011601150114ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a3303080000000100ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a33030a00000002010bffffffffadb5b4d9c20de237a2bfa5543d8d53546fdeffed9b114e307b4d6823ef5fcd2203000000014fffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe010000000100ffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe0300000006011601150114ffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe050000000351009affffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe060000000403ffff7fffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe090000000351009bffffffffb8870d0eb7a246fe332401c2f44c59417d56b30de2640514add2e54132cf4bad0200000006011601150114ffffffffb8870d0eb7a246fe332401c2f44c59417d56b30de2640514add2e54132cf4bad04000000045b5a5193ffffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a010000000151ffffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a08000000025d5effffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a0a000000045b5a5193ffffffffcc68b898c71166468049c9a4130809555908c30f3c88c07e6d28d2f6a6bb486b06000000020051ffffffffcc68b898c71166468049c9a4130809555908c30f3c88c07e6d28d2f6a6bb486b0800000003028000ffffffffce1cba7787ec167235879ca17f46bd4bfa405f9e3e2e35c544537bbd65a5d9620100000006011601150114ffffffffce1cba7787ec167235879ca17f46bd4bfa405f9e3e2e35c544537bbd65a5d962030000000704ffffff7f7693ffffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb5829010000000100ffffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb582907000000025d5effffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb582909000000025b5affffffffd878941d1968d5027129e4b462aead4680bcce392c099d50f294063a528dad9c030000000161ffffffffd878941d1968d5027129e4b462aead4680bcce392c099d50f294063a528dad9c06000000034f4f93ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a0200000006011601150114ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a0300000003016f92ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a050000000704ffffff7f7693ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a08000000025173fffffffff24629f6d9f2b7753e1b6fe1104f8554de1ce6be0dfb4f262a28c38587ed5b34060000000151ffffffff0290051000000000001976a914954659bcb93fdad012a00d825a9bce69dc7c6a2688ac800c49110000000008517a01158874528700000000".from_hex().unwrap();

    let output_hex = vec![
      "085279011688745387".from_hex().unwrap(),
      "08007a011488745287".from_hex().unwrap(),
      "03825587".from_hex().unwrap(),
      "0177".from_hex().unwrap(),
      "024f9c".from_hex().unwrap(),
      "0476636768".from_hex().unwrap(),
      "09709393588893935687".from_hex().unwrap(),
      "03016e87".from_hex().unwrap(),
      "046e7b8887".from_hex().unwrap(),
      "019e".from_hex().unwrap(),
      "0493011587".from_hex().unwrap(),
      "056362675168".from_hex().unwrap(),
      "08517a011588745287".from_hex().unwrap(),
      "0705feffffff0087".from_hex().unwrap(),
      "0482011a87".from_hex().unwrap(),
      "066301ba675168".from_hex().unwrap(),
      "020087".from_hex().unwrap(),
      // There are 35 more ..
    ];

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Vec<Script> = output_hex.iter().map(|hex| deserialize(hex.clone()).ok().expect("scriptpk")).collect();

    for (n, script) in script_pk.iter().enumerate() {
      let mut stack = vec![];
      assert_eq!(tx.input[n].script_sig.evaluate(&mut stack, None), Ok(()));
      assert_eq!(script.evaluate(&mut stack, Some((&tx, n))), Ok(()));
      assert!(stack.len() >= 1);
      assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
    }
  }

  #[test]
  fn script_eval_testnet_failure_3() {
    // For SIGHASH_SINGLE signatures, the unsigned txouts are null, that is,
    // have blank script and value **** (u64)-1 *****
    // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
    let tx_hex = "01000000062c4fb29a89bfe568586dd52c4db39c3daed014bce2d94f66d79dadb82bd83000000000004847304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f01ffffffff5b1015187325285e42c022e0c8388c0bd00a7efb0b28cd0828a5e9575bc040010000000049483045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a81ffffffffc0e15d72865802279f4f5cd13fc86749ce27aac9fd4ba5a8b57c973a82d04a01000000004a493046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4502ffffffff4a1b2b51da86ee82eadce5d3b852aa8f9b3e63106d877e129c5cf450b47f5c02000000004a493046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db182ffffffff61a3e0d8305112ea97d9a2c29b258bd047cf7169c70b4136ba66feffee680f030000000049483045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a6003ffffffffc7d6933e5149568d8b77fbd3f88c63e4e2449635c22defe02679492e7cb926030000000048473044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf83ffffffff0700e1f505000000001976a914c311d13cfbaa1fc8d364a8e89feb1985de58ae3988ac80d1f008000000001976a914eb907923b86af59d3fd918478546c7a234586caf88ac00c2eb0b000000001976a9141c88b9d44e5fc327025157c75af73774758ba68088ac80b2e60e000000001976a914142c0947df1df159b2367a0e1328efb5b76b62bd88ac00a3e111000000001976a914616bffc03acbb416ccf76a048a9bbb974c0504c488ac8093dc14000000001976a9141d5e6e993d168384864c3a92216b9b77560d436488ac804eacab060000001976a914aa9da4a3a4ddc7398ae467eddaf80d743349d6e988ac00000000".from_hex().unwrap();

    let output_hex = vec![
      "232102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac".from_hex().unwrap(),
      "232102f71546fc597e63e2a72dadeeeb50c0ca64079a5a530cb01dd939716d41e9d480ac".from_hex().unwrap(),
      "2321031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43ac".from_hex().unwrap(),
      "23210249c6a76e37c2fcd56687dde6b75bbdf72fcdeeab6fe81561a9c41ac90d9d1f48ac".from_hex().unwrap(),
      "2321035c100972ff8c572dc80eaa15a958ab99064d7c6b9e55f0e6408dec11edd4debbac".from_hex().unwrap(),
      "232103837725cf7377d40a965f082fa6a942d39d9c2433c6d3c7bb4fa262e7d0d19defac".from_hex().unwrap(),
    ];

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Vec<Script> = output_hex.iter().map(|hex| deserialize(hex.clone()).ok().expect("scriptpk")).collect();

    for (n, script) in script_pk.iter().enumerate() {
      let mut stack = vec![];
      assert_eq!(tx.input[n].script_sig.evaluate(&mut stack, None), Ok(()));
      assert_eq!(script.evaluate(&mut stack, Some((&tx, n))), Ok(()));
      assert!(stack.len() >= 1);
      assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
    }
  }

  #[test]
  fn script_eval_testnet_failure_4() {
    // Multisig
    // txid 067cb44dcbd1e3b16eed2482cbe462a461896d4eec891935020a97158f1c100b
    let tx_hex = "01000000018feacff32dfee2218f7873c11087c65b5e7890ad2395da7d4a3e9a7b77bd23f8000000009300483045022100f76f485db0632f4a7fb3c95a5c0eae7b5d0e885f87ac4991e429b3c0f3c444ad0220155a281d7d9bb13ad013df8057a3d43f45de2702ba10b976164fbfcd4be452db014830450221008aa307b332eb0c96bf7c25c7d3c04ae75f071ed652f18dac55dedec7262aef6702203f0a46856b8b9acfac475f1056f04bf50e41aa967c401b85bea3ef20e470d27501ffffffff0100f2052a010000001976a9140550f9aedabdd2ee0424f53f26faeff1b899cc1688ac00000000".from_hex().unwrap();

    let output_hex = "4752210266816de738c62ad789119fdb13131faa13f588359484ca61d0515cdcc7648ecd21025fe4a325d96f109529734af5de80b961274de5720c30646c398202e5d555adca52ae".from_hex().unwrap();

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Script = deserialize(output_hex.clone()).ok().expect("scriptpk");

    let mut stack = vec![];
    assert_eq!(tx.input[0].script_sig.evaluate(&mut stack, None), Ok(()));
    assert_eq!(script_pk.evaluate(&mut stack, Some((&tx, 0))), Ok(()));
    assert!(stack.len() >= 1);
    assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
  }

  #[test]
  fn script_eval_testnet_failure_5() {
    // Pushes in the dead half of OP_IF's should still skip over all the data (OP_PUSH[0..75]
    // txid 4d0bbf6348726a49600171033e456548a09b246829d649e77b929caf242ae6e7
    let tx_hex = "01000000017c19a5b0b84188bca5decac0dc8582f5f5ff003b1a4d705181ec5d9620c1f64600000000940048304502207d02ce76875b1b3f2b7af9e45954af1ab531da6ab3edd471aa9148f139c8bad1022100f0f85fd987e90a131f2e311acdfe212925e218ffa5cf79e84e9890c2ddbdbd450148304502207d02ce76875b1b3f2b7af9e45954af1ab531da6ab3edd471aa9148f139c8bad1022100f0f85fd987e90a131f2e311acdfe212925e218ffa5cf79e84e9890c2ddbdbd450151ffffffff0100e1f505000000001976a91403efb01790d098aef3752449a94a1dc593e527cd88ac00000000".from_hex().unwrap();

    let output_hex = "b36352210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02ef210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02ef52ae67a820080af0b0156c5dd12c820b2b1b4fbfa315d05ac5a0ea2f9a657d4c8881d0869f88a820080af0b0156c5dd12c820b2b1b4fbfa315d05ac5a0ea2f9a657d4c8881d0869f88210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02efac68".from_hex().unwrap();

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Script = deserialize(output_hex.clone()).ok().expect("scriptpk");

    let mut stack = vec![];
    assert_eq!(tx.input[0].script_sig.evaluate(&mut stack, None), Ok(()));
    assert_eq!(script_pk.evaluate(&mut stack, Some((&tx, 0))), Ok(()));
    assert!(stack.len() >= 1);
    assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
  }

  #[test]
  fn script_eval_testnet_failure_6() {
    // Pushes in the dead half of OP_IF's should still skip over all the data (OP_PUSHDATA1 2 4)
    // txid a2119ab5f90270836643665183b21e114daaa6dfdc1bdd7525e1187aa153a229
    let tx_hex = "01000000015e0767f6b58b766d922c6ddd6afc46af9d21c613754bd7cb8010adf0c9c090d2010000000401010100ffffffff0180f0fa02000000001976a914993bcb95575ecda9e7106a30f42232b8e89917c388ac00000000".from_hex().unwrap();

    let output_hex = "0c63ff4c0778657274726f7668".from_hex().unwrap();

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Script = deserialize(output_hex.clone()).ok().expect("scriptpk");

    let mut stack = vec![];
    assert_eq!(tx.input[0].script_sig.evaluate(&mut stack, None), Ok(()));
    assert_eq!(script_pk.evaluate(&mut stack, Some((&tx, 0))), Ok(()));
    assert!(stack.len() >= 1);
    assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
  }

  #[test]
  fn script_eval_testnet_failure_7() {
    // txid 2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1
    let tx_hex = "01000000022f196cf1e5bd426a04f07b882c893b5b5edebad67da6eb50f066c372ed736d5f000000006a47304402201f81ac31b52cb4b1ceb83f97d18476f7339b74f4eecd1a32c251d4c3cccfffa402203c9143c18810ce072969e4132fdab91408816c96b423b2be38eec8a3582ade36012102aa5a2b334bd8f135f11bc5c477bf6307ff98ed52d3ed10f857d5c89adf5b02beffffffffff8755f073f1170c0d519457ffc4acaa7cb2988148163b5dc457fae0fe42aa19000000009200483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a530347304402206da827fb26e569eb740641f9c1a7121ee59141703cbe0f903a22cc7d9a7ec7ac02204729f989b5348b3669ab020b8c4af01acc4deaba7c0d9f8fa9e06b2106cbbfeb01ffffffff010000000000000000016a00000000".from_hex().unwrap();

    let output_hex = vec![
      "1976a91419660c27383b347112e92caba64fb1d07e9f63bf88ac".from_hex().unwrap(),
      "91483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53037552210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7152ae".from_hex().unwrap(),
    ];

    let tx: Transaction = deserialize(tx_hex.clone()).ok().expect("transaction");
    let script_pk: Vec<Script> = output_hex.iter().map(|hex| deserialize(hex.clone()).ok().expect("scriptpk")).collect();

    for (n, script) in script_pk.iter().enumerate() {
      let mut stack = vec![];
      assert_eq!(tx.input[n].script_sig.evaluate(&mut stack, None), Ok(()));
      assert_eq!(script.evaluate(&mut stack, Some((&tx, n))), Ok(()));
      assert!(stack.len() >= 1);
      assert_eq!(read_scriptbool(stack.pop().unwrap().as_slice()), true);
    }
  }
}


