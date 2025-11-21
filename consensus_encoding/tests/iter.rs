use hex::BytesToHexIter;

use bitcoin_consensus_encoding::{Encodable, ArrayEncoder, Encoder2, EncodableByteIter};

struct TestArray<const N: usize>([u8; N]);

impl<const N: usize> Encodable for TestArray<N> {
    type Encoder<'s>
        = ArrayEncoder<N>
    where
        Self: 's;

    fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix(self.0) }
}

struct TestCatArray<const N: usize, const M: usize>([u8; N], [u8; M]);

impl<const N: usize, const M: usize> Encodable for TestCatArray<N, M> {
    type Encoder<'s>
        = Encoder2<ArrayEncoder<N>, ArrayEncoder<M>>
    where
        Self: 's;

    fn encoder(&self) -> Self::Encoder<'_> { Encoder2::new(
            ArrayEncoder::without_length_prefix(self.0),
            ArrayEncoder::without_length_prefix(self.1),
        )
    }
}

#[test]
fn hex_iter() {
    let data = TestArray([255u8, 240, 9, 135]);
    let byte_iter = EncodableByteIter::new(&data);
    let mut iter = BytesToHexIter::new(byte_iter, hex::Case::Upper);

    let expect_str = "FFF00987";
    for byte in expect_str.chars() {
        let iter_byte = iter.next().unwrap();
        assert_eq!(iter_byte, byte);
    }
    let none = iter.next();
    assert_eq!(none, None);
}

#[test]
fn hex_iter_cat_encoder() {
    let data = TestCatArray([222u8, 173], [190u8, 239]);
    let byte_iter = EncodableByteIter::new(&data);
    let mut iter = BytesToHexIter::new(byte_iter, hex::Case::Lower);

    let expect_str = "deadbeef";
    for byte in expect_str.chars() {
        let iter_byte = iter.next().unwrap();
        assert_eq!(iter_byte, byte);
    }
    let none = iter.next();
    assert_eq!(none, None);
}
