use bitcoin_consensus_encoding::{ArrayEncoder, Encodable, Encoder2, Encoder3, EncoderByteIter};
use hex::BytesToHexIter;

struct TestArray<const N: usize>([u8; N]);

impl<const N: usize> Encodable for TestArray<N> {
    type Encoder<'e>
        = ArrayEncoder<N>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix(self.0) }
}

struct TestCatArray<const N: usize, const M: usize>([u8; N], [u8; M]);

impl<const N: usize, const M: usize> Encodable for TestCatArray<N, M> {
    type Encoder<'e>
        = Encoder2<ArrayEncoder<N>, ArrayEncoder<M>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            ArrayEncoder::without_length_prefix(self.0),
            ArrayEncoder::without_length_prefix(self.1),
        )
    }
}

struct TestCatArray3<const N: usize, const M: usize, const L: usize>([u8; N], [u8; M], [u8; L]);

impl<const N: usize, const M: usize, const L: usize> Encodable for TestCatArray3<N, M, L> {
    type Encoder<'e>
        = Encoder3<ArrayEncoder<N>, ArrayEncoder<M>, ArrayEncoder<L>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder3::new(
            ArrayEncoder::without_length_prefix(self.0),
            ArrayEncoder::without_length_prefix(self.1),
            ArrayEncoder::without_length_prefix(self.2),
        )
    }
}

#[test]
fn hex_iter() {
    let data = TestArray([255u8, 240, 9, 135]);
    let byte_iter = EncoderByteIter::new(data.encoder());
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
    let byte_iter = EncoderByteIter::new(data.encoder());
    let mut iter = BytesToHexIter::new(byte_iter, hex::Case::Lower);

    let expect_str = "deadbeef";
    for byte in expect_str.chars() {
        let iter_byte = iter.next().unwrap();
        assert_eq!(iter_byte, byte);
    }
    let none = iter.next();
    assert_eq!(none, None);
}

// This is purposely testing that nth(0) works correctly.
#[allow(clippy::iter_nth_zero)]
#[test]
fn nth() {
    let data = TestArray([255u8, 240, 9, 135]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.nth(2).unwrap(), 9);
    assert_eq!(byte_iter.nth(0).unwrap(), 135);
    assert!(byte_iter.nth(42).is_none());

    let data = TestCatArray([222u8, 173], [190u8, 239]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.nth(1).unwrap(), 173);
    assert_eq!(byte_iter.nth(1).unwrap(), 239);
    assert!(byte_iter.nth(42).is_none());

    let data = TestCatArray3([0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.nth(5).unwrap(), 5);
    assert_eq!(byte_iter.peek_chunk(), [6, 7]);
}

#[test]
fn peek_chunk() {
    let data = TestArray([255u8, 240, 9, 135]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.peek_chunk(), [255u8, 240, 9, 135]);
    assert_eq!(byte_iter.next().unwrap(), 255);
    assert_eq!(byte_iter.peek_chunk(), [240, 9, 135]);

    let data = TestCatArray([222u8, 173], [190u8, 239]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.peek_chunk(), [222u8, 173]);
    assert_eq!(byte_iter.next().unwrap(), 222);
    assert_eq!(byte_iter.peek_chunk(), [173]);
    assert_eq!(byte_iter.next().unwrap(), 173);
    assert_eq!(byte_iter.peek_chunk(), [190, 239]);

    let data = TestCatArray([], [21u8, 42]);
    let mut byte_iter = EncoderByteIter::new(data.encoder());
    assert_eq!(byte_iter.peek_chunk(), [21, 42]);
    assert_eq!(byte_iter.next().unwrap(), 21);
    assert_eq!(byte_iter.peek_chunk(), [42]);
    assert_eq!(byte_iter.next().unwrap(), 42);
    assert!(byte_iter.next().is_none());
}
