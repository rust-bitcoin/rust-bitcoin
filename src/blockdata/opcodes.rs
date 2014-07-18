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

//! # Opcodes
//!
//! Bitcoin's script uses a stack-based assembly language. This module defines
//! the mapping from assembler instructions to bytes.
//!

pub static FALSE:     u8 = 0x00;
pub static TRUE:      u8 = 0x51;
pub static PUSHDATA1: u8 = 0x4C;
pub static PUSHDATA2: u8 = 0x4D;
pub static PUSHDATA4: u8 = 0x4E;
pub static CHECKSIG:  u8 = 0xAC;


