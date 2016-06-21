// Rust Bitcoin Library
// Written in 2014 by
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

//! # Miscellaneous functions
//!
//! Various utility functions

use blockdata::opcodes;
use util::Error;
use util::iter::Pairable;

/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, Error> {
    let mut v = vec![];
    let mut iter = s.chars().pair();
    // Do the parsing
    try!(iter.by_ref().fold(Ok(()), |e, (f, s)| 
        if e.is_err() { e }
        else {
            match (f.to_digit(16), s.to_digit(16)) {
                (None, _) => Err(Error::Detail(
                    format!("expected hex, got {:}", f),
                    Box::new(Error::ParseFailed)
                )),
                (_, None) => Err(Error::Detail(
                    format!("expected hex, got {:}", s),
                    Box::new(Error::ParseFailed)
                )),
                (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
            }
        }
    ));
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err(Error::Detail(
            "hexstring of odd length".to_owned(),
            Box::new(Error::ParseFailed)
        )),
        None => Ok(v)
    }
}

/// Dump an error message to the screen
/// TODO all uses of this should be replaced with some sort of logging infrastructure
pub fn consume_err<T>(s: &str, res: Result<T, Error>) {
    match res {
        Ok(_) => {},
        Err(e) => { println!("{}: {:?}", s, e); }
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
        if &haystack[i..(i + needle.len())] == needle {
            for j in i..top {
                haystack.swap(j + needle.len(), j);
            }
            n_deleted += 1;
            // This is ugly but prevents infinite loop in case of overflow
            let overflow = top < needle.len();
            top = top.wrapping_sub(needle.len());
            if overflow { break; }
        } else {
            i += match opcodes::All::from((*haystack)[i]).classify() {
                opcodes::Class::PushBytes(n) => n as usize + 1,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => 2,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => 3,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => 5,
                _ => 1
            };
        }
    }
    haystack.truncate(top.wrapping_add(needle.len()));
    n_deleted
}

#[cfg(test)]
mod tests {
    use super::script_find_and_remove;
    use super::hex_bytes;

    #[test]
    fn test_script_find_and_remove() {
        let mut v = vec![101u8, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109];

        assert_eq!(script_find_and_remove(&mut v, &[]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 105]), 0);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 106, 107]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[104, 108, 109]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[101]), 1);
        assert_eq!(v, vec![102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[102]), 3);
        assert_eq!(v, vec![103, 104, 103, 104, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[103, 104]), 2);
        assert_eq!(v, vec![103]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[103]), 1);
        assert_eq!(v, vec![]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
    }

    #[test]
    fn test_script_codesep_remove() {
        let mut s = vec![33u8, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 81];
        assert_eq!(script_find_and_remove(&mut s, &[171]), 2);
        assert_eq!(s, vec![33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 81]);
    }

    #[test]
    fn test_hex_bytes() {
        assert_eq!(&hex_bytes("abcd").unwrap(), &[171u8, 205]);
        assert!(hex_bytes("abcde").is_err());
        assert!(hex_bytes("aBcDeF").is_ok());
        assert!(hex_bytes("aBcD4eFL").is_err());
    }
}

