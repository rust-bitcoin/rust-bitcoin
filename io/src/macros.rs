// SPDX-License-Identifier: CC0-1.0

/// Implements [`crate::Write`] for `$ty`.
// See below for docs (docs.rs build enables all features).
#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        impl<$($bounded_ty: $bounds),*> $crate::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> $crate::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> $crate::Result<()> {
                $flush_fn(self)
            }
        }
    }
}

/// Implements [`crate::Write`] for `$ty`.
///
/// Also implements [`std::io::Write`] for `$ty` if `bitcoin_io` has the `std` feature enabled.
///
/// # Arguments
///
/// * `$ty` - the type used to implement the two traits.
/// * `write_fn` - the function called by the `Write::write` trait method.
/// * `flush_fn` - the function called by the `Write::flush` trait method.
/// * `$bounded_ty: $bounds` - optional trait bounds if required.
#[cfg(feature = "std")]
#[macro_export]
macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        impl<$($bounded_ty: $bounds),*> std::io::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> std::io::Result<()> {
                $flush_fn(self)
            }
        }

        impl<$($bounded_ty: $bounds),*> $crate::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> $crate::Result<usize> {
                $write_fn(self, buf)
            }
            #[inline]
            fn flush(&mut self) -> $crate::Result<()> {
                $flush_fn(self)
            }
        }
    }
}
