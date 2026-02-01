// SPDX-License-Identifier: CC0-1.0

use crate::consensus::encode::{ReadExt, WriteExt};
use crate::io::Cursor;

#[kani::unwind(10)] // Unwind recursion for read/write operations
#[kani::proof]
fn check_compact_size_roundtrip() {
    let x: u32 = kani::any();
    let mut bytes = [0u8; 9];
    let mut cursor = Cursor::new(&mut bytes[..]);
    cursor.emit_compact_size(x).unwrap();
    cursor.set_position(0);
    let y = cursor.read_compact_size().unwrap();
    assert_eq!(u64::from(x), y);
}

#[kani::unwind(10)]
#[kani::proof]
fn check_compact_size_large_u64_roundtrip() {
    let x: u64 = kani::any();
    kani::assume(x > 0xFFFFFFFF); // Force 9-byte encoding
    let mut bytes = [0u8; 9];
    let mut cursor = Cursor::new(&mut bytes[..]);
    cursor.emit_compact_size(x).unwrap();
    cursor.set_position(0);
    let y = cursor.read_compact_size().unwrap();
    assert_eq!(x, y);
}
