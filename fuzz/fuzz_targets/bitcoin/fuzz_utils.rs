pub fn consume_random_bytes<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.is_empty() {
        return &[];
    }

    let length = (data[0] as usize) % (data.len() + 1);
    let (bytes, rest) = data.split_at(length);
    *data = rest;

    bytes
}
