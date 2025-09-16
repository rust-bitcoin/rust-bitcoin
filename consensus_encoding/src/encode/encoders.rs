// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".
//!
//! These encoders should not be used directly. Instead, when implementing the
//! [`super::Encodable`] trait on a type, you should define a newtype around one
//! or more of these encoders, and pass through the [`Encoder`] implementation
//! to your newtype. This avoids leaking encoding implementation details to the
//! users of your type.
//!
//! For implementing these newtypes, we provide the [`encoder_newtype`] macro.
//!

use super::Encoder;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: Option<&'sl [u8]>,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl: Some(sl) } }
}

impl<'e, 'sl> Encoder<'e> for BytesEncoder<'sl> {
    fn current_chunk(&self) -> Option<&[u8]> { self.sl }

    fn advance(&mut self) -> bool {
        self.sl = None;
        false
    }
}

/// An encoder for a single array.
pub struct ArrayEncoder<const N: usize> {
    arr: Option<[u8; N]>,
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr: Some(arr) } }
}

impl<'e, const N: usize> Encoder<'e> for ArrayEncoder<N> {
    fn current_chunk(&self) -> Option<&[u8]> { self.arr.as_ref().map(|x| &x[..]) }

    fn advance(&mut self) -> bool {
        self.arr = None;
        false
    }
}

/// An encoder which encodes two objects, one after the other.
pub struct Encoder2<A, B> {
    enc_idx: usize,
    enc_1: A,
    enc_2: B,
}

impl<A, B> Encoder2<A, B> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B) -> Self { Self { enc_idx: 0, enc_1, enc_2 } }
}

impl<'e, A: Encoder<'e>, B: Encoder<'e>> Encoder<'e> for Encoder2<A, B> {
    fn current_chunk(&self) -> Option<&[u8]> {
        if self.enc_idx == 0 {
            self.enc_1.current_chunk()
        } else {
            self.enc_2.current_chunk()
        }
    }

    fn advance(&mut self) -> bool {
        if self.enc_idx == 0 {
            if !self.enc_1.advance() {
                self.enc_idx += 1;
            }
            true
        } else {
            self.enc_2.advance()
        }
    }
}

// For now we implement every higher encoder by composing Encoder2s, because
// I'm lazy and this is trivial both to write and to review. For efficiency, we
// should eventually unroll all of these. There are only a couple of them. The
// unrolled versions should be macro-izable, if we want to do that.

/// An encoder which encodes three objects, one after the other.
pub struct Encoder3<A, B, C> {
    inner: Encoder2<Encoder2<A, B>, C>,
}

impl<A, B, C> Encoder3<A, B, C> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), enc_3) }
    }
}

impl<'e, A: Encoder<'e>, B: Encoder<'e>, C: Encoder<'e>> Encoder<'e> for Encoder3<A, B, C> {
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    fn advance(&mut self) -> bool { self.inner.advance() }
}

/// An encoder which encodes four objects, one after the other.
pub struct Encoder4<A, B, C, D> {
    inner: Encoder2<Encoder2<A, B>, Encoder2<C, D>>,
}

impl<A, B, C, D> Encoder4<A, B, C, D> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D) -> Self {
        Self { inner: Encoder2::new(Encoder2::new(enc_1, enc_2), Encoder2::new(enc_3, enc_4)) }
    }
}

impl<'e, A: Encoder<'e>, B: Encoder<'e>, C: Encoder<'e>, D: Encoder<'e>> Encoder<'e>
    for Encoder4<A, B, C, D>
{
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    fn advance(&mut self) -> bool { self.inner.advance() }
}

/// An encoder which encodes six objects, one after the other.
pub struct Encoder6<A, B, C, D, E, F> {
    inner: Encoder2<Encoder3<A, B, C>, Encoder3<D, E, F>>,
}

impl<A, B, C, D, E, F> Encoder6<A, B, C, D, E, F> {
    /// Constructs a new composite encoder.
    pub fn new(enc_1: A, enc_2: B, enc_3: C, enc_4: D, enc_5: E, enc_6: F) -> Self {
        Self {
            inner: Encoder2::new(
                Encoder3::new(enc_1, enc_2, enc_3),
                Encoder3::new(enc_4, enc_5, enc_6),
            ),
        }
    }
}

impl<
        'e,
        A: Encoder<'e>,
        B: Encoder<'e>,
        C: Encoder<'e>,
        D: Encoder<'e>,
        E: Encoder<'e>,
        F: Encoder<'e>,
    > Encoder<'e> for Encoder6<A, B, C, D, E, F>
{
    fn current_chunk(&self) -> Option<&[u8]> { self.inner.current_chunk() }
    fn advance(&mut self) -> bool { self.inner.advance() }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    // Run the encoder i.e., use it to encode into a vector.
    fn run_encoder<'e>(mut encoder: impl Encoder<'e>) -> Vec<u8> {
        let mut vec = Vec::new();
        while let Some(chunk) = encoder.current_chunk() {
            vec.extend_from_slice(chunk);
            encoder.advance();
        }
        vec
    }

    #[test]
    fn encode_byte_slice_without_prefix() {
        let obj = [1u8, 2, 3];

        let encoder = BytesEncoder::without_length_prefix(&obj);
        let got = run_encoder(encoder);

        assert_eq!(got, obj);
    }

    #[test]
    fn encode_empty_byte_slice_without_prefix() {
        let obj = [];

        let encoder = BytesEncoder::without_length_prefix(&obj);
        let got = run_encoder(encoder);

        assert_eq!(got, obj);
    }
}
