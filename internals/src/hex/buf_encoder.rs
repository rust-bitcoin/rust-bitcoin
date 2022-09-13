//! Implements a buffered encoder.
//!
//! The main type of this module is [`BufEncoder`] which provides buffered hex encoding. Such is
//! faster than the usual `write!(f, "{02x}", b)?` in a for loop because it reduces dynamic
//! dispatch and decreases the number of allocations if a `String` is being created.

pub use out_bytes::OutBytes;

use super::Case;

/// Implements `OutBytes`
///
/// This prevents the rest of the crate from accessing the field of `OutBytes`.
mod out_bytes {
    /// A byte buffer that can only be written-into.
    ///
    /// You shouldn't concern yourself with this, just call `BufEncoder::new` with your array.
    ///
    /// This prepares the API for potential future support of `[MaybeUninit<u8>]`. We don't want to use
    /// `unsafe` until it's proven to be needed but if it does we have an easy, compatible upgrade
    /// option.
    ///
    /// We also don't bother with unsized type because the immutable version is useless and this avoids
    /// `unsafe` while we don't want/need it.
    pub struct OutBytes<'a>(&'a mut [u8]);

    impl<'a> OutBytes<'a> {
        /// Returns the first `len` bytes as initialized.
        ///
        /// Not `unsafe` because we don't use `unsafe` (yet).
        ///
        /// ## Panics
        ///
        /// The method panics if `len` is out of bounds.
        #[cfg_attr(rust_v_1_46, track_caller)]
        pub(crate) fn assume_init(&self, len: usize) -> &[u8] {
            &self.0[..len]
        }

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
        pub(crate) fn len(&self) -> usize {
            self.0.len()
        }
    }

    macro_rules! impl_from_array {
        ($($len:expr),* $(,)?) => {
            $(
                impl<'a> From<&'a mut [u8; $len]> for OutBytes<'a> {
                    fn from(value: &'a mut [u8; $len]) -> Self {
                        OutBytes(value)
                    }
                }
            )*
        }
    }

    // As a sanity check we only provide conversions for even, non-empty arrays.
    // Weird lengths 66 and 130 are provided for serialized public keys.
    impl_from_array!(2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 64, 66, 128, 130, 256, 512, 1024, 2048, 4096, 8192);
}

/// Hex-encodes bytes into the provided buffer.
///
/// This is an important building block for fast hex-encoding. Because string writing tools
/// provided by `core::fmt` involve dynamic dispatch and don't allow reserving capacity in strings
/// buffering the hex and then formatting it is significantly faster.
pub struct BufEncoder<'a> {
    buf: OutBytes<'a>,
    pos: usize,
}

impl<'a> BufEncoder<'a> {
    /// Creates an empty `BufEncoder`.
    ///
    /// This is usually used with uninitialized (zeroed) byte array allocated on stack.
    /// This can only be constructed with an even-length, non-empty array.
    #[inline]
    pub fn new<T: Into<OutBytes<'a>>>(buf: T) -> Self {
        let buf = buf.into();
        BufEncoder {
            buf,
            pos: 0,
        }
    }

    /// Encodes `byte` as hex in given `case` and appends it to the buffer.
    ///
    /// ## Panics
    ///
    /// The method panics if the buffer is full.
    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    pub fn put_byte(&mut self, byte: u8, case: Case) {
        self.buf.write(self.pos, &super::byte_to_hex(byte, case.table()));
        self.pos += 2;
    }

    /// Encodes `bytes` as hex in given `case` and appends them to the buffer.
    ///
    /// ## Panics
    ///
    /// The method panics if the bytes wouldn't fit the buffer.
    #[inline]
    #[cfg_attr(rust_v_1_46, track_caller)]
    pub fn put_bytes(&mut self, bytes: &[u8], case: Case) {
        // Panic if the result wouldn't fit address space to not waste time and give the optimizer
        // more opportunities.
        let double_len = bytes.len().checked_mul(2).expect("overflow");
        assert!(double_len <= self.buf.len() - self.pos);
        for byte in bytes {
            self.put_byte(*byte, case);
        }
    }

    /// Returns true if no more bytes can be written into the buffer.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Returns the written bytes as a hex `str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.buf.assume_init(self.pos)).expect("we only write ASCII")
    }

    /// Resets the buffer to become empty.
    #[inline]
    pub fn clear(&mut self) {
        self.pos = 0;
    }
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
        encoder.put_byte(42, Case::Lower);
        assert_eq!(encoder.as_str(), "2a");
        assert!(encoder.is_full());
        encoder.clear();
        assert!(!encoder.is_full());
        encoder.put_byte(42, Case::Upper);
        assert_eq!(encoder.as_str(), "2A");
        assert!(encoder.is_full());
    }

    #[test]
    fn single_byte_oversized_buf() {
        let mut buf = [0u8; 4];
        let mut encoder = BufEncoder::new(&mut buf);
        encoder.put_byte(42, Case::Lower);
        assert_eq!(encoder.as_str(), "2a");
        assert!(!encoder.is_full());
        encoder.clear();
        encoder.put_byte(42, Case::Upper);
        assert_eq!(encoder.as_str(), "2A");
        assert!(!encoder.is_full());
    }

    #[test]
    fn two_bytes() {
        let mut buf = [0u8; 4];
        let mut encoder = BufEncoder::new(&mut buf);
        encoder.put_byte(42, Case::Lower);
        encoder.put_byte(255, Case::Lower);
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
    fn same_as_fmt() {
        use core::fmt::{self, Write};

        struct Writer {
            buf: [u8; 2],
            pos: usize,
        }

        impl Writer {
            fn as_str(&self) -> &str {
                core::str::from_utf8(&self.buf[..self.pos]).unwrap()
            }
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

        let mut writer = Writer {
            buf: [0u8; 2],
            pos: 0,
        };
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
