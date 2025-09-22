// SPDX-License-Identifier: CC0-1.0

use bitcoin_io::{BufRead, Cursor};

#[test]
fn cursor_bufread_fill_buf_past_end_returns_empty() {
    const BUF_LEN: usize = 8;
    let v = [1_u8; BUF_LEN];
    let mut c = Cursor::new(v);

    // Move position past end
    c.set_position((BUF_LEN * 2) as u64);
    let slice = BufRead::fill_buf(&mut c).unwrap();
    assert!(slice.is_empty());
}

#[test]
fn cursor_bufread_consume_saturates() {
    const BUF_LEN: usize = 8;
    let v = [1_u8; BUF_LEN];
    let mut c = Cursor::new(v);

    // Initially full buffer available
    let slice = BufRead::fill_buf(&mut c).unwrap();
    assert_eq!(slice.len(), BUF_LEN);

    // Try to consume more than available: should not panic, saturate to end
    c.consume(BUF_LEN * 2);

    // Now we should be at/after end; fill_buf should be empty
    let slice = BufRead::fill_buf(&mut c).unwrap();
    assert!(slice.is_empty());
}
