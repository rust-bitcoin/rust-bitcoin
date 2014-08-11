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

/// Search for `needle` in the vector `haystack` and remove every
/// instance of it, returning the number of instances removed.
pub fn find_and_remove<T:Eq+::std::fmt::Show>(haystack: &mut Vec<T>, needle: &[T]) -> uint {
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
      i += 1;
    }
  }
  haystack.truncate(top + needle.len());
  n_deleted
}

#[cfg(test)]
mod tests {
  use std::prelude::*;

  use super::find_and_remove;
  use super::hex_bytes;

  #[test]
  fn test_find_and_remove() {
    let mut v = vec![1u, 2, 3, 4, 2, 3, 4, 2, 3, 4, 5, 6, 7, 8, 9];

    assert_eq!(find_and_remove(&mut v, []), 0);
    assert_eq!(find_and_remove(&mut v, [5, 5, 5]), 0);
    assert_eq!(v, vec![1, 2, 3, 4, 2, 3, 4, 2, 3, 4, 5, 6, 7, 8, 9]);

    assert_eq!(find_and_remove(&mut v, [5, 6, 7]), 1);
    assert_eq!(v, vec![1, 2, 3, 4, 2, 3, 4, 2, 3, 4, 8, 9]);

    assert_eq!(find_and_remove(&mut v, [4, 8, 9]), 1);
    assert_eq!(v, vec![1, 2, 3, 4, 2, 3, 4, 2, 3]);

    assert_eq!(find_and_remove(&mut v, [1]), 1);
    assert_eq!(v, vec![2, 3, 4, 2, 3, 4, 2, 3]);

    assert_eq!(find_and_remove(&mut v, [2]), 3);
    assert_eq!(v, vec![3, 4, 3, 4, 3]);

    assert_eq!(find_and_remove(&mut v, [3, 4]), 2);
    assert_eq!(v, vec![3]);

    assert_eq!(find_and_remove(&mut v, [5, 5, 5]), 0);
    assert_eq!(find_and_remove(&mut v, [5]), 0);
    assert_eq!(find_and_remove(&mut v, [3]), 1);
    assert_eq!(v, vec![]);

    assert_eq!(find_and_remove(&mut v, [5, 5, 5]), 0);
    assert_eq!(find_and_remove(&mut v, [5]), 0);
  }

  #[test]
  fn test_hex_bytes() {
    assert_eq!(hex_bytes("abcd").unwrap().as_slice(), [171u8, 205].as_slice());
    assert!(hex_bytes("abcde").is_err());
    assert!(hex_bytes("aBcDeF").is_ok());
    assert!(hex_bytes("aBcD4eFL").is_err());
  }
}

