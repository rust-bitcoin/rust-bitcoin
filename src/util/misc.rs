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

//! # Miscellaneous functions
//!
//! Various utility functions

use std::io::{Error, Result, ErrorKind};

use blockdata::opcodes;
use util::iter::Pairable;

/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> Result<Vec<u8>> {
  let mut v = vec![];
  let mut iter = s.chars().pair();
  // Do the parsing
  try!(iter.fold(Ok(()), |e, (f, s)| 
    if e.is_err() { return e; }
    else {
      match (f.to_digit(16), s.to_digit(16)) {
        (None, _) => return Err(Error {
          kind: ErrorKind::InvalidInput,
          desc: "invalid hex character",
          detail: Some(format!("expected hex, got {:}", f))
        }),
        (_, None) => return Err(Error {
          kind: ErrorKind::InvalidInput,
          desc: "invalid hex character",
          detail: Some(format!("expected hex, got {:}", s))
        }),
        (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
      }
    }
  ));
  // Check that there was no remainder
  match iter.remainder() {
    Some(_) => Err(Error {
      kind: ErrorKind::InvalidInput,
      desc: "hexstring of odd length",
      detail: None
    }),
    None => Ok(v)
  }
}

/// Prepend the detail of an IoResult's error with some text to get poor man's backtracing
pub fn prepend_err<T>(s: &str, res: Result<T>) -> Result<T> {
  res.map_err(|err| {
    Error {
      kind: err.kind,
      desc: err.desc,
      detail: Some(format!("{}: {}", s, match err.detail { Some(s) => s, None => String::new() }))
    }
  })
}

/// Dump an error message to the screen
pub fn consume_err<T>(s: &str, res: Result<T>) {
  match res {
    Ok(_) => {},
    Err(e) => { println!("{}: {}", s, e); }
  };
}

/// Search for `needle` in the vector `haystack` and remove every
/// instance of it, returning the number of instances removed.
/// Loops through the vector opcode by opcode, skipping pushed data.
pub fn script_find_and_remove(haystack: &mut Vec<u8>, needle: &[u8]) -> usize {
  if needle.len() > haystack.len() { return 0; }
  if needle.len() == 0 { return 0; }

  let mut top = haystack.len() - needle.len();
  let mut n_deleted = 0;

  let mut i = 0;
  while i <= top {
    if haystack.slice(i, i + needle.len()) == needle {
      let v = haystack.as_mut_slice();
      for j in range(i, top) {
        v.swap(j + needle.len(), j);
      }
      n_deleted += 1;
      // This is ugly but prevents infinite loop in case of overflow
      let overflow = top < needle.len();
      top -= needle.len();
      if overflow { break; }
    } else {
      i += match Opcode::from_u8((*haystack)[i]).classify() {
        opcodes::PushBytes(n) => n + 1,
        opcodes::Ordinary(opcodes::OP_PUSHDATA1) => 2,
        opcodes::Ordinary(opcodes::OP_PUSHDATA2) => 3,
        opcodes::Ordinary(opcodes::OP_PUSHDATA4) => 5,
        _ => 1
      };
    }
  }
  haystack.truncate(top + needle.len());
  n_deleted
}

#[cfg(test)]
mod tests {
  use std::prelude::*;

  use super::script_find_and_remove;
  use super::hex_bytes;

  #[test]
  fn test_script_find_and_remove() {
    let mut v = vec![101u8, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109];

    assert_eq!(script_find_and_remove(&mut v, []), 0);
    assert_eq!(script_find_and_remove(&mut v, [105, 105, 105]), 0);
    assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109]);

    assert_eq!(script_find_and_remove(&mut v, [105, 106, 107]), 1);
    assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 108, 109]);

    assert_eq!(script_find_and_remove(&mut v, [104, 108, 109]), 1);
    assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103]);

    assert_eq!(script_find_and_remove(&mut v, [101]), 1);
    assert_eq!(v, vec![102, 103, 104, 102, 103, 104, 102, 103]);

    assert_eq!(script_find_and_remove(&mut v, [102]), 3);
    assert_eq!(v, vec![103, 104, 103, 104, 103]);

    assert_eq!(script_find_and_remove(&mut v, [103, 104]), 2);
    assert_eq!(v, vec![103]);

    assert_eq!(script_find_and_remove(&mut v, [105, 105, 5]), 0);
    assert_eq!(script_find_and_remove(&mut v, [105]), 0);
    assert_eq!(script_find_and_remove(&mut v, [103]), 1);
    assert_eq!(v, vec![]);

    assert_eq!(script_find_and_remove(&mut v, [105, 105, 5]), 0);
    assert_eq!(script_find_and_remove(&mut v, [105]), 0);
  }

  #[test]
  fn test_script_codesep_remove() {
    let mut s = vec![33u8, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 81];
    assert_eq!(script_find_and_remove(&mut s, [171]), 2);
    assert_eq!(s, vec![33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 81]);
  }

  #[test]
  fn test_hex_bytes() {
    assert_eq!(hex_bytes("abcd").unwrap().as_slice(), [171u8, 205].as_slice());
    assert!(hex_bytes("abcde").is_err());
    assert!(hex_bytes("aBcDeF").is_ok());
    assert!(hex_bytes("aBcD4eFL").is_err());
  }
}

