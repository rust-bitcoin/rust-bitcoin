use test::Bencher;

use crate::{ChaCha20, Key, Nonce};

#[bench]
pub fn chacha20_10(bh: &mut Bencher) {
    let key = Key::new([0u8; 32]);
    let nonce = Nonce::new([0u8; 12]);
    let count = 1;
    let mut chacha = ChaCha20::new(key, nonce, count);
    let mut bytes = [0u8; 10];
    bh.iter(|| {
        chacha.apply_keystream(&mut bytes[..]);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn chacha20_1k(bh: &mut Bencher) {
    let key = Key::new([0u8; 32]);
    let nonce = Nonce::new([0u8; 12]);
    let count = 1;
    let mut chacha = ChaCha20::new(key, nonce, count);
    let mut bytes = [0u8; 1024];
    bh.iter(|| {
        chacha.apply_keystream(&mut bytes[..]);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn chacha20_64k(bh: &mut Bencher) {
    let key = Key::new([0u8; 32]);
    let nonce = Nonce::new([0u8; 12]);
    let count = 1;
    let mut chacha = ChaCha20::new(key, nonce, count);
    let mut bytes = [0u8; 65536];
    bh.iter(|| {
        chacha.apply_keystream(&mut bytes[..]);
    });
    bh.bytes = bytes.len() as u64;
}
