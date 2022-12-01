// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Utility functions.
//!
//! Functions needed by all parts of the Bitcoin library.
//!

/// The `misc` module was moved and re-named to `sign_message`.
pub mod misc {
    use crate::prelude::*;

    /// Search for `needle` in the vector `haystack` and remove every
    /// instance of it, returning the number of instances removed.
    /// Loops through the vector opcode by opcode, skipping pushed data.
    // For why we deprecated see: https://github.com/rust-bitcoin/rust-bitcoin/pull/1259#discussion_r968613736
    #[deprecated(since = "0.30.0", note = "No longer supported")]
    pub fn script_find_and_remove(haystack: &mut Vec<u8>, needle: &[u8]) -> usize {
        use crate::blockdata::opcodes;

        if needle.len() > haystack.len() {
            return 0;
        }
        if needle.is_empty() {
            return 0;
        }

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
                if overflow {
                    break;
                }
            } else {
                i += match opcodes::All::from((*haystack)[i]).classify(opcodes::ClassifyContext::Legacy) {
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
}
