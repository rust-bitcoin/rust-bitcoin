//! Test using wrapper types as we expect the lib to be used.

#![cfg(feature = "std")]

use consensus_encoding as encoding;
use encoding::{ArrayEncoder, BytesEncoder, Encodable, Encoder2, SliceEncoder};

encoding::encoder_newtype! {
    /// An encoder that uses an inner `ArrayEncoder`.
    pub struct TestArrayEncoder(ArrayEncoder<4>);
}

encoding::encoder_newtype! {
    /// An encoder that uses an inner `BytesEncoder`.
    pub struct TestBytesEncoder<'e>(BytesEncoder<'e>);
}

#[test]
fn array_encoder() {
    #[derive(Debug, Default, Clone)]
    pub struct Test(u32);

    impl Encodable for Test {
        type Encoder<'e> = TestArrayEncoder;
        fn encoder(&self) -> Self::Encoder<'_> {
            TestArrayEncoder(ArrayEncoder::without_length_prefix(self.0.to_le_bytes()))
        }
    }

    let t = Test(0xcafe_babe); // Encodes using an array.

    let want = [0xbe, 0xba, 0xfe, 0xca];
    let got = encoding::encode_to_vec(&t);

    assert_eq!(got, want);
}

#[test]
fn bytes_encoder_without_length_prefix() {
    #[derive(Debug, Default, Clone)]
    pub struct Test(Vec<u8>);

    impl Encodable for Test {
        type Encoder<'e>
            = TestBytesEncoder<'e>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> {
            TestBytesEncoder(BytesEncoder::without_length_prefix(self.0.as_ref()))
        }
    }

    let t = Test(vec![0xca, 0xfe]);

    let want = [0xca, 0xfe];
    let got = encoding::encode_to_vec(&t);

    assert_eq!(got, want);
}

#[test]
fn bytes_encoder_with_length_prefix() {
    #[derive(Debug, Default, Clone)]
    pub struct Test(Vec<u8>);

    impl Encodable for Test {
        type Encoder<'e>
            = TestBytesEncoder<'e>
        where
            Self: 'e;

        fn encoder(&self) -> Self::Encoder<'_> {
            TestBytesEncoder(BytesEncoder::with_length_prefix(self.0.as_ref()))
        }
    }

    let t = Test(vec![0xca, 0xfe]);

    let want = [0x02, 0xca, 0xfe];
    let got = encoding::encode_to_vec(&t);

    assert_eq!(got, want);
}

#[test]
fn two_encoder() {
    #[derive(Debug, Default, Clone)]
    pub struct Test {
        a: Vec<u8>, // Encode without prefix.
        b: Vec<u8>, // Encode with prefix.
    }

    impl Encodable for Test {
        type Encoder<'e> = Encoder2<TestBytesEncoder<'e>, TestBytesEncoder<'e>>;

        fn encoder(&self) -> Self::Encoder<'_> {
            let a = TestBytesEncoder(BytesEncoder::without_length_prefix(self.a.as_ref()));
            let b = TestBytesEncoder(BytesEncoder::with_length_prefix(self.b.as_ref()));

            Encoder2::new(a, b)
        }
    }

    let t = Test { a: vec![0xca, 0xfe], b: (vec![0xba, 0xbe]) };

    let want = [0xca, 0xfe, 0x02, 0xba, 0xbe];
    let got = encoding::encode_to_vec(&t);

    assert_eq!(got, want);
}

#[test]
fn slice_encoder() {
    #[derive(Debug, Default, Clone)]
    pub struct Test(Vec<Inner>);

    encoding::encoder_newtype! {
        /// An encoder that uses an inner `SliceEncoder`.
        pub struct TestEncoder<'e>(SliceEncoder<'e, Inner>);
    }

    impl Encodable for Test {
        type Encoder<'a>
            = TestEncoder<'a>
        where
            Self: 'a;

        fn encoder(&self) -> Self::Encoder<'_> {
            TestEncoder(SliceEncoder::with_length_prefix(&self.0))
        }
    }

    #[derive(Debug, Default, Clone)]
    pub struct Inner(u32);

    encoding::encoder_newtype! {
        /// The encoder for the [`Inner`] type.
        pub struct InnerArrayEncoder(ArrayEncoder<4>);
    }

    impl Encodable for Inner {
        type Encoder<'e> = InnerArrayEncoder;
        fn encoder(&self) -> Self::Encoder<'_> {
            // Big-endian to make reading the test assertion easier.
            InnerArrayEncoder(ArrayEncoder::without_length_prefix(self.0.to_be_bytes()))
        }
    }

    let t = Test(vec![Inner(0xcafe_babe), Inner(0xdead_beef)]);
    let encoded = encoding::encode_to_vec(&t);

    let want = [0x02, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef];
    assert_eq!(encoded, want);
}
