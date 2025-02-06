use test::Bencher;

use crate::{ripemd160, Hash, HashEngine};

#[bench]
pub fn ripemd160_10(bh: &mut Bencher) {
    let mut engine = ripemd160::Hash::engine();
    let bytes = [1u8; 10];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn ripemd160_1k(bh: &mut Bencher) {
    let mut engine = ripemd160::Hash::engine();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn ripemd160_64k(bh: &mut Bencher) {
    let mut engine = ripemd160::Hash::engine();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
