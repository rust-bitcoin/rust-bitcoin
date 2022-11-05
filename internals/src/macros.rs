//! Various macros used by the Rust Bitcoin ecosystem.
//!

/// Implements standard array methods for a given wrapper type.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
        impl $thing {
            /// Converts the object to a raw pointer.
            #[inline]
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            /// Converts the object to a mutable raw pointer.
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            /// Returns the length of the object as an array.
            #[inline]
            pub fn len(&self) -> usize { $len }

            /// Returns whether the object, as an array, is empty. Always false.
            #[inline]
            pub fn is_empty(&self) -> bool { false }

            /// Returns a reference the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[$ty; $len] { &self.0 }

            /// Returns the underlying bytes.
            #[inline]
            pub fn to_bytes(self) -> [$ty; $len] {
                // We rely on `Copy` being implemented for $thing so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$thing>();

                self.0
            }
        }

        impl<'a> core::convert::From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}

/// Implements `Debug` by calling through to `Display`.
#[macro_export]
macro_rules! debug_from_display {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}

/// Asserts a boolean expression at compile time.
#[macro_export]
macro_rules! const_assert {
    ($x:expr) => {{
        const _: [(); 0 - !$x as usize] = [];
    }};
}
