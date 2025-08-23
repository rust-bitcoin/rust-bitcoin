// SPDX-License-Identifier: CC0-1.0

//! Collection of "standard encoders".

/// An encoder for a single byte slice.
use super::Encoder;

/// An encoder for a single byte slice.
pub struct BytesEncoder<'sl> {
    sl: &'sl [u8],
    done: bool,
}

impl<'sl> BytesEncoder<'sl> {
    /// Constructs a byte encoder which encodes the given byte slice, with no length
    /// prefix.
    pub fn without_length_prefix(sl: &'sl [u8]) -> Self { Self { sl, done: false } }
}

impl<'sl> Encoder for BytesEncoder<'sl> {
    fn advance(&mut self) -> Option<&[u8]> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(self.sl)
        }
    }

    fn unadvance(&mut self) { self.done = false; }
}

/// An encoder for a single array.
pub struct ArrayEncoder<const N: usize> {
    arr: [u8; N],
    done: bool,
}

impl<const N: usize> ArrayEncoder<N> {
    /// Constructs an encoder which encodes the array with no length prefix.
    pub fn without_length_prefix(arr: [u8; N]) -> Self { Self { arr, done: false } }
}

impl<const N: usize> Encoder for ArrayEncoder<N> {
    fn advance(&mut self) -> Option<&[u8]> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(&self.arr)
        }
    }

    fn unadvance(&mut self) { self.done = false; }
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

impl<A: Encoder, B: Encoder> Encoder for Encoder2<A, B> {
    fn advance(&mut self) -> Option<&[u8]> {
        if self.enc_idx == 0 {
            if let Some(res) = self.enc_1.advance() {
                return Some(res);
            }
            self.enc_idx += 1;
        }
        self.enc_2.advance()
    }

    fn unadvance(&mut self) {
        if self.enc_idx == 0 {
            self.enc_1.unadvance();
        } else {
            self.enc_2.unadvance();
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

impl<A: Encoder, B: Encoder, C: Encoder> Encoder for Encoder3<A, B, C> {
    fn advance(&mut self) -> Option<&[u8]> { self.inner.advance() }
    fn unadvance(&mut self) { self.inner.unadvance() }
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

impl<A: Encoder, B: Encoder, C: Encoder, D: Encoder> Encoder for Encoder4<A, B, C, D> {
    fn advance(&mut self) -> Option<&[u8]> { self.inner.advance() }
    fn unadvance(&mut self) { self.inner.unadvance() }
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

impl<A: Encoder, B: Encoder, C: Encoder, D: Encoder, E: Encoder, F: Encoder> Encoder
    for Encoder6<A, B, C, D, E, F>
{
    fn advance(&mut self) -> Option<&[u8]> { self.inner.advance() }
    fn unadvance(&mut self) { self.inner.unadvance() }
}
