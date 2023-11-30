//! Public macros for porvide.d for users to be able implement our `io::Write` trait.

#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` for users using
/// that feature. In any case, this crate's `io::Write` feature will be implemented for the given
/// type, even if indirectly.
#[cfg(not(feature = "std"))]
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

#[macro_export]
/// Because we cannot provide a blanket implementation of [`std::io::Write`] for all implementers
/// of this crate's `io::Write` trait, we provide this macro instead.
///
/// This macro will implement `Write` given a `write` and `flush` fn, either by implementing the
/// crate's native `io::Write` trait directly, or a more generic trait from `std` for users using
/// that feature. In any case, this crate's `io::Write` feature will be implemented for the given
/// type, even if indirectly.
#[cfg(feature = "std")]
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
    }
}
