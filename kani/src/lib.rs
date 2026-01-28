#[cfg(kani)]
mod verification {
    use bitcoin::io::Cursor;

    use bitcoin::consensus::encode::{ReadExt, WriteExt};

    #[kani::proof]
    fn check_compact_size_roundtrip() {
        let x: u64 = kani::any();
        // Compact Size can be up to 9 bytes
        let mut buffer = [0u8; 9];
        let mut cursor = Cursor::new(&mut buffer[..]);

        // Encode
        // emit_compact_size returns Result<usize, io::Error>
        cursor.emit_compact_size(x).unwrap();

        // Reset cursor to start
        cursor.set_position(0);

        // Decode
        // read_compact_size returns Result<u64, Error>
        let y = cursor.read_compact_size().unwrap();

        assert_eq!(x, y);
    }
}
