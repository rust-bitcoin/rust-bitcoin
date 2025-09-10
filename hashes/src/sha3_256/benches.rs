use test::Bencher;

use crate::{Hash, HashEngine};

#[bench]
pub fn sha3_256_10(bh: &mut Bencher) {
    let mut engine = crate::sha3_256::Hash::engine();
    let bytes = [1u8; 10];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_256_1k(bh: &mut Bencher) {
    let mut engine = crate::sha3_256::Hash::engine();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_256_64k(bh: &mut Bencher) {
    let mut engine = crate::sha3_256::Hash::engine();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
