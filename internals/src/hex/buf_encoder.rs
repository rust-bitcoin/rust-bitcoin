//! Implements a buffered encoder.
//!
//! The main type of this module is [`BufEncoder`] which provides buffered hex encoding. Such is
//! faster than the usual `write!(f, "{02x}", b)?` in a for loop because it reduces dynamic
//! dispatch and decreases the number of allocations if a `String` is being created.

use core::borrow::Borrow;

pub use out_bytes::OutBytes;

use super::Case;

/// Trait for types that can be soundly converted to `OutBytes`.
///
/// To protect the API from future breakage this sealed trait guards which types can be used with
/// the `Encoder`. Currently it is implemented for byte arrays of various interesting lengths.
///
/// ## Safety
///
/// This is not `unsafe` yet but the `as_out_bytes` should always return the same reference if the
/// same reference is supplied. IOW the returned memory address and length should be the same if
/// the input memory address and length are the same.
///
/// If the trait ever becomes `unsafe` this will be required for soundness.
pub trait AsOutBytes: out_bytes::Sealed {
    /// Performs the conversion.
    fn as_out_bytes(&self) -> &OutBytes;

    /// Performs the conversion.
    fn as_mut_out_bytes(&mut self) -> &mut OutBytes;
}

/// A buffer with compile-time-known length.
///
/// This is essentially `Default + AsOutBytes` but supports lengths 1.41 doesn't.
pub trait FixedLenBuf: Sized + AsOutBytes {
    /// Creates an uninitialized buffer.
    ///
    /// The current implementtions initialize the buffer with zeroes but it should be treated a
    /// uninitialized anyway.
    fn uninit() -> Self;
}

/// Implements `OutBytes`
///
/// This prevents the rest of the crate from accessing the field of `OutBytes`.
mod out_bytes {
    use super::AsOutBytes;

    /// A byte buffer that can only be written-into.
    ///
    /// You shouldn't concern yourself with this, just call `BufEncoder::new` with your array.
    ///
    /// This prepares the API for potential future support of `[MaybeUninit<u8>]`. We don't want to use
    /// `unsafe` until it's proven to be needed but if it does we have an easy, compatible upgrade
    /// option.
    ///
    /// Warning: `repr(transparent)` is an internal implementation detail and **must not** be
    /// relied on!
    #[repr(transparent)]
    pub struct OutBytes([u8]);

    impl OutBytes {
        /// Returns the first `len` bytes as initialized.
        ///
        /// Not `unsafe` because we don't use `unsafe` (yet).
        ///
        /// ## Panics
        ///
        /// The method panics if `len` is out of bounds.
        #[cfg_attr(rust_v_1_46, track_caller)]
        pub(crate) fn assume_init(&self, len: usize) -> &[u8] { &self.0[..len] }

        /// Writes given bytes into the buffer.
        ///
        /// ## Panics
        ///
        /// The method panics if pos is out of bounds or `bytes` don't fit into the buffer.
        #[cfg_attr(rust_v_1_46, track_caller)]
        pub(crate) fn write(&mut self, pos: usize, bytes: &[u8]) {
            self.0[pos..(pos + bytes.len())].copy_from_slice(bytes);
        }

        /// Returns the length of the buffer.
        pub(crate) fn len(&self) -> usize { self.0.len() }

        fn from_bytes(slice: &[u8]) -> &Self {
            // SAFETY: copied from std
            // conversion of reference to pointer of the same referred type is always sound,
            // including in unsized types.
            // Thanks to repr(transparent) the types have the same layout making the other
            // conversion sound.
            // The pointer was just created from a reference that's still alive so dereferencing is
            // sound.
            unsafe { &*(slice as *const [u8] as *const Self) }
        }

        fn from_mut_bytes(slice: &mut [u8]) -> &mut Self {
            // SAFETY: copied from std
            // conversion of reference to pointer of the same referred type is always sound,
            // including in unsized types.
            // Thanks to repr(transparent) the types have the same layout making the other
            // conversion sound.
            // The pointer was just created from a reference that's still alive so dereferencing is
            // sound.
            unsafe { &mut *(slice as *mut [u8] as *mut Self) }
        }
    }

    macro_rules! impl_from_array {
        ($($len:expr),* $(,)?) => {
            $(
                impl super::FixedLenBuf for [u8; $len] {
                    fn uninit() -> Self {
                        [0u8; $len]
                    }
                }

                impl AsOutBytes for [u8; $len] {
                    fn as_out_bytes(&self) -> &OutBytes {
                        OutBytes::from_bytes(self)
                    }

                    fn as_mut_out_bytes(&mut self) -> &mut OutBytes {
                        OutBytes::from_mut_bytes(self)
                    }
                }

                impl Sealed for [u8; $len] {}

                impl<'a> super::super::display::DisplayHex for &'a [u8; $len / 2] {
                    type Display = super::super::display::DisplayArray<core::slice::Iter<'a, u8>, [u8; $len]>;
                    fn as_hex(self) -> Self::Display {
                        super::super::display::DisplayArray::new(self.iter())
                    }

                    fn hex_reserve_suggestion(self) -> usize {
                        $len
                    }
                }
            )*
        }
    }

    impl<T: AsOutBytes + ?Sized> AsOutBytes for &'_ mut T {
        fn as_out_bytes(&self) -> &OutBytes { (**self).as_out_bytes() }

        fn as_mut_out_bytes(&mut self) -> &mut OutBytes { (**self).as_mut_out_bytes() }
    }

    impl<T: AsOutBytes + ?Sized> Sealed for &'_ mut T {}

    impl AsOutBytes for OutBytes {
        fn as_out_bytes(&self) -> &OutBytes { self }

        fn as_mut_out_bytes(&mut self) -> &mut OutBytes { self }
    }

    impl Sealed for OutBytes {}

    // As a sanity check we only provide conversions for even, non-empty arrays.
    // Weird lengths 66 and 130 are provided for serialized public keys.
    impl_from_array!(
        2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 40, 64, 66, 128, 130, 256, 512,
        1024, 2048, 4096, 8192
    );

    /// Prevents outside crates from implementing the trait
    pub trait Sealed {}
}

/// Hex-encodes bytes into the provided buffer.
///
/// This is an important building block for fast hex-encoding. Because string writing tools
/// provided by `core::fmt` involve dynamic dispatch and don't allow reserving capacity in strings
/// buffering the hex and then formatting it is significantly faster.
pub struct BufEncoder<T: AsOutBytes> {
    buf: T,
    pos: usize,
}

impl<T: AsOutBytes> BufEncoder<T> {
    /// Creates an empty `BufEncoder`.
    ///
    /// This is usually used with uninitialized (zeroed) byte array allocated on stack.
    /// This can only be constructed with an even-length, non-empty array.
    #[inline]
    pub fn new(buf: T) -> Self { BufEncoder { buf, pos: 0 } }

    /// Encodes `byte` as hex in given `case` and appends it to the buffer.
    ///
    /// ## Panics
    ///
    /// The method panics if the buffer is full.
    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    pub fn put_byte(&mut self, byte: u8, case: Case) {
        self.buf.as_mut_out_bytes().write(self.pos, &super::byte_to_hex(byte, case.table()));
        self.pos += 2;
    }

    /// Encodes `bytes` as hex in given `case` and appends them to the buffer.
    ///
    /// ## Panics
    ///
    /// The method panics if the bytes wouldn't fit the buffer.
    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    pub fn put_bytes<I>(&mut self, bytes: I, case: Case)
    where
        I: IntoIterator,
        I::Item: Borrow<u8>,
    {
        self.put_bytes_inner(bytes.into_iter(), case)
    }

    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    fn put_bytes_inner<I>(&mut self, bytes: I, case: Case)
    where
        I: Iterator,
        I::Item: Borrow<u8>,
    {
        // May give the compiler better optimization opportunity
        if let Some(max) = bytes.size_hint().1 {
            assert!(max <= self.space_remaining());
        }
        for byte in bytes {
            self.put_byte(*byte.borrow(), case);
        }
    }

    /// Encodes as many `bytes` as fit into the buffer as hex and return the remainder.
    ///
    /// This method works just like `put_bytes` but instead of panicking it returns the unwritten
    /// bytes. The method returns an empty slice if all bytes were written
    #[must_use = "this may write only part of the input buffer"]
    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    pub fn put_bytes_min<'a>(&mut self, bytes: &'a [u8], case: Case) -> &'a [u8] {
        let to_write = self.space_remaining().min(bytes.len());
        self.put_bytes(&bytes[..to_write], case);
        &bytes[to_write..]
    }

    /// Returns true if no more bytes can be written into the buffer.
    #[inline]
    pub fn is_full(&self) -> bool { self.pos == self.buf.as_out_bytes().len() }

    /// Returns the written bytes as a hex `str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.buf.as_out_bytes().assume_init(self.pos))
            .expect("we only write ASCII")
    }

    /// Resets the buffer to become empty.
    #[inline]
    pub fn clear(&mut self) { self.pos = 0; }

    /// How many bytes can be written to this buffer.
    ///
    /// Note that this returns the number of bytes before encoding, not number of hex digits.
    #[inline]
    pub fn space_remaining(&self) -> usize { (self.buf.as_out_bytes().len() - self.pos) / 2 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let mut buf = [0u8; 2];
        let encoder = BufEncoder::new(&mut buf);
        assert_eq!(encoder.as_str(), "");
        assert!(!encoder.is_full());
    }

    #[test]
    fn single_byte_exact_buf() {
        let mut buf = [0u8; 2];
        let mut encoder = BufEncoder::new(&mut buf);
        assert_eq!(encoder.space_remaining(), 1);
        encoder.put_byte(42, Case::Lower);
        assert_eq!(encoder.as_str(), "2a");
        assert_eq!(encoder.space_remaining(), 0);
        assert!(encoder.is_full());
        encoder.clear();
        assert_eq!(encoder.space_remaining(), 1);
        assert!(!encoder.is_full());
        encoder.put_byte(42, Case::Upper);
        assert_eq!(encoder.as_str(), "2A");
        assert_eq!(encoder.space_remaining(), 0);
        assert!(encoder.is_full());
    }

    #[test]
    fn single_byte_oversized_buf() {
        let mut buf = [0u8; 4];
        let mut encoder = BufEncoder::new(&mut buf);
        assert_eq!(encoder.space_remaining(), 2);
        encoder.put_byte(42, Case::Lower);
        assert_eq!(encoder.space_remaining(), 1);
        assert_eq!(encoder.as_str(), "2a");
        assert!(!encoder.is_full());
        encoder.clear();
        assert_eq!(encoder.space_remaining(), 2);
        encoder.put_byte(42, Case::Upper);
        assert_eq!(encoder.as_str(), "2A");
        assert_eq!(encoder.space_remaining(), 1);
        assert!(!encoder.is_full());
    }

    #[test]
    fn two_bytes() {
        let mut buf = [0u8; 4];
        let mut encoder = BufEncoder::new(&mut buf);
        encoder.put_byte(42, Case::Lower);
        assert_eq!(encoder.space_remaining(), 1);
        encoder.put_byte(255, Case::Lower);
        assert_eq!(encoder.space_remaining(), 0);
        assert_eq!(encoder.as_str(), "2aff");
        assert!(encoder.is_full());
        encoder.clear();
        assert!(!encoder.is_full());
        encoder.put_byte(42, Case::Upper);
        encoder.put_byte(255, Case::Upper);
        assert_eq!(encoder.as_str(), "2AFF");
        assert!(encoder.is_full());
    }

    #[test]
    fn put_bytes_min() {
        let mut buf = [0u8; 2];
        let mut encoder = BufEncoder::new(&mut buf);
        let remainder = encoder.put_bytes_min(b"", Case::Lower);
        assert_eq!(remainder, b"");
        assert_eq!(encoder.as_str(), "");
        let remainder = encoder.put_bytes_min(b"*", Case::Lower);
        assert_eq!(remainder, b"");
        assert_eq!(encoder.as_str(), "2a");
        encoder.clear();
        let remainder = encoder.put_bytes_min(&[42, 255], Case::Lower);
        assert_eq!(remainder, &[255]);
        assert_eq!(encoder.as_str(), "2a");
    }

    #[test]
    fn same_as_fmt() {
        use core::fmt::{self, Write};

        struct Writer {
            buf: [u8; 2],
            pos: usize,
        }

        impl Writer {
            fn as_str(&self) -> &str { core::str::from_utf8(&self.buf[..self.pos]).unwrap() }
        }

        impl Write for Writer {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                assert!(self.pos <= 2);
                if s.len() > 2 - self.pos {
                    Err(fmt::Error)
                } else {
                    self.buf[self.pos..(self.pos + s.len())].copy_from_slice(s.as_bytes());
                    self.pos += s.len();
                    Ok(())
                }
            }
        }

        let mut writer = Writer { buf: [0u8; 2], pos: 0 };
        let mut buf = [0u8; 2];
        let mut encoder = BufEncoder::new(&mut buf);

        for i in 0..=255 {
            write!(writer, "{:02x}", i).unwrap();
            encoder.put_byte(i, Case::Lower);
            assert_eq!(encoder.as_str(), writer.as_str());
            writer.pos = 0;
            encoder.clear();
        }
        for i in 0..=255 {
            write!(writer, "{:02X}", i).unwrap();
            encoder.put_byte(i, Case::Upper);
            assert_eq!(encoder.as_str(), writer.as_str());
            writer.pos = 0;
            encoder.clear();
        }
    }
}
