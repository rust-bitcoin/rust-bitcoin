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

use std::io::{IoError, IoResult, InvalidInput};

use util::iter::Pairable;

/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> IoResult<Vec<u8>> {
  let mut v = vec![];
  let mut iter = s.chars().pair();
  // Do the parsing
  try!(iter.fold(Ok(()), |e, (f, s)| 
    if e.is_err() { return e; }
    else {
      match (f.to_digit(16), s.to_digit(16)) {
        (None, _) => return Err(IoError {
          kind: InvalidInput,
          desc: "invalid hex character",
          detail: Some(format!("expected hex, got {:}", f))
        }),
        (_, None) => return Err(IoError {
          kind: InvalidInput,
          desc: "invalid hex character",
          detail: Some(format!("expected hex, got {:}", s))
        }),
        (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
      }
    }
  ));
  // Check that there was no remainder
  match iter.remainder() {
    Some(_) => Err(IoError {
      kind: InvalidInput,
      desc: "hexstring of odd length",
      detail: None
    }),
    None => Ok(v)
  }
}

/// Prepend the detail of an IoResult's error with some text to get poor man's backtracing
pub fn prepend_err<T>(s: &str, res: IoResult<T>) -> IoResult<T> {
  res.map_err(|err| {
    IoError {
      kind: err.kind,
      desc: err.desc,
      detail: Some(format!("{:s}: {:}", s, match err.detail { Some(s) => s, None => String::new() }))
    }
  })
}

/// Dump an error message to the screen
pub fn consume_err<T>(s: &str, res: IoResult<T>) {
  match res {
    Ok(_) => {},
    Err(e) => { println!("{:s}: {:}", s, e); }
  };
}

#[cfg(test)]
mod tests {
  use std::prelude::*;

  use util::misc::hex_bytes;

  #[test]
  fn test_hex_bytes() {
    assert_eq!(hex_bytes("abcd").unwrap().as_slice(), [171u8, 205].as_slice());
    assert!(hex_bytes("abcde").is_err());
    assert!(hex_bytes("aBcDeF").is_ok());
    assert!(hex_bytes("aBcD4eFL").is_err());
  }
}

