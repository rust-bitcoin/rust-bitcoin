// SPDX-License-Identifier: CC0-1.0

use core::mem::MaybeUninit;

/// Storage for `N` bytes of payload followed by the 4 checksum bytes.
#[repr(C)]
struct ArrayBuf<const N: usize> {
    _buffer: [MaybeUninit<u8>; N],
    _reserve_for_chksum: [MaybeUninit<u8>; 4],
}

impl<const N: usize> ArrayBuf<N> {
    /// Constructs a new buffer.
    const fn uninit() -> Self {
        Self {
            _buffer: [MaybeUninit::uninit(); N],
            _reserve_for_chksum: [MaybeUninit::uninit(); 4],
        }
    }

    /// Returns the whole buffer, both fields, as a single slice.
    fn as_slice(&self) -> &[MaybeUninit<u8>] {
        let ptr: *const Self = self;
        // SAFETY: `Self` is `size_of::<Self>()` contiguous bytes of `MaybeUninit<u8>` and
        // `MaybeUninit<u8>` has a size of u8/1 byte.
        unsafe {
            core::slice::from_raw_parts(
                ptr.cast::<MaybeUninit<u8>>(),
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// Returns the whole buffer, both fields, as a single mutable slice.
    fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        let ptr: *mut Self = self;
        // SAFETY: As in `as_slice`.
        unsafe {
            core::slice::from_raw_parts_mut(
                ptr.cast::<MaybeUninit<u8>>(),
                core::mem::size_of::<Self>(),
            )
        }
    }
}

/// A vector of bytes, backed by an array of `N + 4` bytes.
pub(crate) struct ExtendedArrayVec<const N: usize> {
    len: usize,
    buf: ArrayBuf<N>,
}

impl<const N: usize> ExtendedArrayVec<N> {
    /// Constructs an empty `ExtendedArrayVec`.
    pub(crate) const fn new() -> Self { Self { len: 0, buf: ArrayBuf::uninit() } }

    /// Returns the number of bytes in `self`.
    pub(crate) fn len(&self) -> usize { self.len }

    /// Returns a reference to the initialized bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        let ptr = self.buf.as_slice().as_ptr().cast::<u8>();
        // SAFETY: `MaybeUninit<u8>` has the same layout as `u8` and the
        // first `len` bytes of the buffer are initialized.
        unsafe { core::slice::from_raw_parts(ptr, self.len) }
    }

    /// Returns a mutable reference to the initialized bytes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        let ptr = self.buf.as_mut_slice().as_mut_ptr().cast::<u8>();
        // SAFETY: As in `as_slice`.
        unsafe { core::slice::from_raw_parts_mut(ptr, self.len) }
    }

    /// Adds a byte to the end of `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if `self` is already at capacity.
    pub(crate) fn try_push(&mut self, val: u8) -> Result<(), super::CapacityExceededError> {
        self.buf
            .as_mut_slice()
            .get_mut(self.len)
            .ok_or(super::CapacityExceededError { capacity: N + 4 })?
            .write(val);
        self.len += 1;
        Ok(())
    }
}