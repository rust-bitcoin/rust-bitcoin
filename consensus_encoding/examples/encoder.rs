// SPDX-License-Identifier: CC0-1.0

//! Example of creating an encoder that encodes a vector of encodable objects.

use consensus_encoding as encoding;
use encoding::{ArrayEncoder, BytesEncoder, Encodable, Encoder, Encoder2, VecEncoder};

fn main() {
    let v = vec![Inner::new(0xcafebabe), Inner::new(0xdeadbeef)];
    let b = vec![0xab, 0xcd];

    let adt = Adt::new(v, b);
    let encoded = encoding::encode_to_vec(&adt);

    // deet, deet, I'm a bot - use little endian.
    let want = [0x02, 0xbe, 0xba, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde, 0x02, 0xab, 0xcd];
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

/// The encoder for the [`Adt`] type.
pub struct AdtEncoder<'e>(Encoder2<VecEncoder<'e, Inner>, BytesEncoder<'e>>);

impl<'e> Encoder<'e> for AdtEncoder<'e> {
    #[inline]
    fn current_chunk(&self) -> Option<&[u8]> { self.0.current_chunk() }

    #[inline]
    fn advance(&mut self) -> bool { self.0.advance() }
}

impl Encodable for Adt {
    type Encoder<'a>
        = AdtEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        let a = VecEncoder::new(self.v.iter().collect::<Vec<&Inner>>());
        let b = BytesEncoder::with_length_prefix(self.b.as_ref());

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
    pub fn to_array(&self) -> [u8; 4] { self.0.to_le_bytes() }
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
