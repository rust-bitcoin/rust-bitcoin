// SPDX-License-Identifier: CC0-1.0

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
        }

        impl<'a> core::convert::From<[$ty; $len]> for $thing {
            fn from(data: [$ty; $len]) -> Self { $thing(data) }
        }

        impl<'a> core::convert::From<&'a [$ty; $len]> for $thing {
            fn from(data: &'a [$ty; $len]) -> Self { $thing(*data) }
        }

        impl<'a> core::convert::TryFrom<&'a [$ty]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [$ty]) -> Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[$ty; $len]> for $thing {
            fn as_ref(&self) -> &[$ty; $len] { &self.0 }
        }

        impl AsMut<[$ty; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        impl AsRef<[$ty]> for $thing {
            fn as_ref(&self) -> &[$ty] { &self.0 }
        }

        impl AsMut<[$ty]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty] { &mut self.0 }
        }

        impl core::borrow::Borrow<[$ty; $len]> for $thing {
            fn borrow(&self) -> &[$ty; $len] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty; $len]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        // The following two are valid because `[T; N]: Borrow<[T]>`
        impl core::borrow::Borrow<[$ty]> for $thing {
            fn borrow(&self) -> &[$ty] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty] { &mut self.0 }
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
