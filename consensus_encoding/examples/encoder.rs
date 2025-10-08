// SPDX-License-Identifier: CC0-1.0

//! Example of creating an encoder that encodes a slice of encodable objects.

use consensus_encoding as encoding;
use encoding::{ArrayEncoder, BytesEncoder, CompactSizeEncoder, Encodable, Encoder2, SliceEncoder};

fn main() {
    let v = vec![Inner::new(0xcafe_babe), Inner::new(0xdead_beef)];
    let b = vec![0xab, 0xcd];

    let adt = Adt::new(v, b);
    let encoded = encoding::encode_to_vec(&adt);

    let want = [0x02, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xcd];
    assert_eq!(encoded, want);
}

/// Some abstract data type.
struct Adt {
    v: Vec<Inner>,
    b: Vec<u8>,
}

impl Adt {
    /// Constructs a new `Adt`.
    pub fn new(v: Vec<Inner>, b: Vec<u8>) -> Self { Self { v, b } }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Adt`] type.
    pub struct AdtEncoder<'e>(Encoder2<Encoder2<CompactSizeEncoder, SliceEncoder<'e, Inner>>, BytesEncoder<'e>>);
}

impl Encodable for Adt {
    type Encoder<'a>
        = AdtEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        let a = Encoder2::new(
            CompactSizeEncoder::new(self.v.len()),
            SliceEncoder::without_length_prefix(&self.v),
        );
        let b = BytesEncoder::without_length_prefix(self.b.as_ref());

        AdtEncoder(Encoder2::new(a, b))
    }
}

/// A simple data type to use as list item.
#[derive(Debug, Default, Clone)]
pub struct Inner(u32);

impl Inner {
    /// Constructs a new `Inner`.
    pub fn new(x: u32) -> Self { Self(x) }

    /// Returns some meaningful 4 byte array for this type.
    pub fn to_array(&self) -> [u8; 4] { self.0.to_be_bytes() }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Inner`] type.
    pub struct InnerEncoder(ArrayEncoder<4>);
}

impl Encodable for Inner {
    type Encoder<'e> = InnerEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        InnerEncoder(ArrayEncoder::without_length_prefix(self.to_array()))
    }
}
