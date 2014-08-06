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

use blockdata::opcodes;
use blockdata::opcodes::Opcode;
use allops = blockdata::opcodes::all;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleDecoder, SimpleEncoder};
use util::thinvec::ThinVec;

#[deriving(PartialEq, Show, Clone)]
/// A Bitcoin script
pub struct Script(ThinVec<u8>);

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[deriving(PartialEq, Eq, Show, Clone)]
pub enum ScriptError {
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
  /// Tried to read an array off the stack as a number when it was more than 4 bytes
  NumericOverflow,
  /// Some stack operation was done with an empty stack
  PopEmptyStack,
  /// An OP_VERIFY happened with an empty stack
  VerifyEmptyStack,
  /// An OP_VERIFY happened with zero on the stack
  VerifyFailed,
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
  v.iter().all(|&w| w == 0)
}

/// Helper to read a script uint
fn read_uint<'a, I:Iterator<&'a u8>>(mut iter: I, size: uint) -> Result<uint, ScriptError> {
  let mut ret = 0;
  for _ in range(0, size) {
    match iter.next() {
      Some(&n) => { ret = (ret << 8) + n as uint; }
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
  pub fn push_opcode(&mut self, data: Opcode) {
    let &Script(ref mut raw) = self;
    raw.push(data as u8);
  }

  /// Evaluate the script, modifying the stack in place
  pub fn evaluate(&self, stack: &mut Vec<Vec<u8>>) -> Result<(), ScriptError> {
    let &Script(ref raw) = self;

    let mut iter = raw.iter();
    let mut exec_stack = vec![true];
    let mut alt_stack = vec![];

    for byte in iter {
      let executing = exec_stack.iter().all(|e| *e);
      // The definitions of all these categories are in opcodes.rs
      match (executing, allops::Opcode::from_u8(*byte).classify()) {
        // Illegal operations mean failure regardless of execution state
        (_, opcodes::IllegalOp)       => return Err(IllegalOpcode),
        // Push number
        (true, opcodes::PushNum(n))   => stack.push(build_scriptint(n as i64)),
        // Push data
        (true, opcodes::PushBytes(n)) => stack.push(iter.take(n).map(|n| *n).collect()),
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
              let n = try!(read_uint(iter, 1));
              let read: Vec<u8> = iter.take(n as uint).map(|n| *n).collect();
              if read.len() < n as uint { return Err(EarlyEndOfScript); }
              stack.push(read);
            }
            opcodes::OP_PUSHDATA2 => {
              let n = try!(read_uint(iter, 2));
              let read: Vec<u8> = iter.take(n as uint).map(|n| *n).collect();
              if read.len() < n as uint { return Err(EarlyEndOfScript); }
              stack.push(read);
            }
            opcodes::OP_PUSHDATA4 => {
              let n = try!(read_uint(iter, 4));
              let read: Vec<u8> = iter.take(n as uint).map(|n| *n).collect();
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
              let top = stack.len();
              let eq = (*stack)[top - 2] == (*stack)[top - 1];
              stack.push(build_scriptint(if eq { 1 } else { 0 }));
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
            // TODO: crypto
            opcodes::OP_CHECKSIG => {}
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

  use super::{Script, build_scriptint, read_scriptint};

  use network::serialize::{deserialize, serialize};
  use blockdata::opcodes;
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
    script.push_opcode(opcodes::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
    script.push_opcode(opcodes::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
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
}


