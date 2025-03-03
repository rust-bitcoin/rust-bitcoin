pub fn consume_random_bytes<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.is_empty() {
        return &[];
    }

    let length = (data[0] as usize) % (data.len() + 1);
    let (bytes, rest) = data.split_at(length);
    *data = rest;

    bytes
}

#[allow(dead_code)]
pub fn consume_u64(data: &mut &[u8]) -> u64 {
    // We need at least 8 bytes to read a u64
    if data.len() < 8 {
        return 0;
    }

    let (u64_bytes, rest) = data.split_at(8);
    *data = rest;

    u64::from_le_bytes([
        u64_bytes[0],
        u64_bytes[1],
        u64_bytes[2],
        u64_bytes[3],
        u64_bytes[4],
        u64_bytes[5],
        u64_bytes[6],
        u64_bytes[7],
    ])
}
