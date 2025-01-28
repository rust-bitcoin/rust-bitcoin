use test::Bencher;

use crate::{sha256, Hash, HashEngine};

#[bench]
pub fn sha256_10(bh: &mut Bencher) {
    let mut engine = sha256::Hash::engine();
    let bytes = [1u8; 10];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_1k(bh: &mut Bencher) {
    let mut engine = sha256::Hash::engine();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_64k(bh: &mut Bencher) {
    let mut engine = sha256::Hash::engine();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
