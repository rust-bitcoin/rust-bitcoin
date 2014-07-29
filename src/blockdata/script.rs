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
use std::io::IoResult;
use serialize::json;

use network::serialize::Serializable;
use blockdata::opcodes;
use util::thinvec::ThinVec;

#[deriving(PartialEq, Show, Clone)]
/// A Bitcoin script
pub struct Script(ThinVec<u8>);

impl Script {
  /// Creates a new empty script
  pub fn new() -> Script { Script(ThinVec::new()) }

  /// Adds instructions to push an integer onto the stack. Integers are
  /// encoded as little-endian signed-magnitude numbers, but there are
  /// dedicated opcodes to push some small integers.
  pub fn push_int(&mut self, data: int) {
    // We can special-case -1, 1-16
    if data == -1 || (data >= 1 && data <=16) {
      let &Script(ref mut raw) = self;
      raw.push(data as u8 + opcodes::TRUE);
      return;
    }
    // We can also special-case zero
    if data == 0 {
      let &Script(ref mut raw) = self;
      raw.push(opcodes::FALSE);
      return;
    }
    // Otherwise encode it as data
    self.push_scriptint(data);
  }

  /// Adds instructions to push an integer onto the stack, using the explicit
  /// encoding regardless of the availability of dedicated opcodes.
  pub fn push_scriptint(&mut self, data: int) {
    let neg = data < 0;

    let mut abs = if neg { -data } else { data } as uint;
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
    // Finally we put the encoded int onto the stack
    self.push_slice(v.as_slice());
  }

  /// Adds instructions to push some arbitrary data onto the stack
  pub fn push_slice(&mut self, data: &[u8]) {
    let &Script(ref mut raw) = self;
    // Start with a PUSH opcode
    match data.len() {
      n if n < opcodes::PUSHDATA1 as uint => { raw.push(n as u8); },
      n if n < 0x100 => {
        raw.push(opcodes::PUSHDATA1);
        raw.push(n as u8);
      },
      n if n < 0x10000 => {
        raw.push(opcodes::PUSHDATA2);
        raw.push((n % 0x100) as u8);
        raw.push((n / 0x100) as u8);
      },
      n if n < 0x100000000 => {
        raw.push(opcodes::PUSHDATA4);
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
  pub fn push_opcode(&mut self, data: u8) {
    let &Script(ref mut raw) = self;
    raw.push(data);
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
impl Serializable for Script {
  fn serialize(&self) -> Vec<u8> {
    let &Script(ref data) = self;
    data.serialize()
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<Script> {
    let raw = Serializable::deserialize(iter);
    raw.map(|ok| Script(ok))
  }
}

#[cfg(test)]
mod test {
  use std::io::IoResult;

  use network::serialize::Serializable;
  use blockdata::script::Script;
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
    script.push_opcode(opcodes::CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
    script.push_opcode(opcodes::CHECKSIG); comp.push(0xACu8); assert_eq!(script, Script(comp.clone()));
  }

  #[test]
  fn script_serialize() {
    let hex_script = hex_bytes("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52").unwrap();
    let script: IoResult<Script> = Serializable::deserialize(hex_script.iter().map(|n| *n));
    assert!(script.is_ok());
    assert_eq!(script.unwrap().serialize().as_slice(), hex_script.as_slice());
  }
}


