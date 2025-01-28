use test::Bencher;

use crate::{sha1, Hash, HashEngine};

#[bench]
pub fn sha1_10(bh: &mut Bencher) {
    let mut engine = sha1::Hash::engine();
    let bytes = [1u8; 10];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_1k(bh: &mut Bencher) {
    let mut engine = sha1::Hash::engine();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_64k(bh: &mut Bencher) {
    let mut engine = sha1::Hash::engine();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        engine.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
