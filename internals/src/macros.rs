// SPDX-License-Identifier: CC0-1.0

//! Various macros used by the Rust Bitcoin ecosystem.

/// Implements standard array methods for a given wrapper type.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
        impl $thing {
            /// Creates `Self` by wrapping `bytes`.
            #[inline]
            pub fn from_byte_array(bytes: [u8; $len]) -> Self { Self(bytes) }

            /// Returns a reference the underlying byte array.
            #[inline]
            pub fn as_byte_array(&self) -> &[u8; $len] { &self.0 }

            /// Returns the underlying byte array.
            #[inline]
            pub fn to_byte_array(self) -> [u8; $len] {
                // We rely on `Copy` being implemented for $thing so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$thing>();

                self.0
            }

            /// Returns a slice of the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8] { &self.0 }

            /// Copies the underlying bytes into a new `Vec`.
            #[cfg(feature = "alloc")]
            #[inline]
            pub fn to_bytes(&self) -> alloc::vec::Vec<u8> { self.0.to_vec() }

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

            fn try_from(data: &'a [$ty]) -> core::result::Result<Self, Self::Error> {
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
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter,
            ) -> core::result::Result<(), core::fmt::Error> {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}

/// Asserts a boolean expression at compile time.
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(; $message:expr)?) => {
        const _: () = {
            if !$x {
                // We can't use formatting in const, only concating literals.
                panic!(concat!("assertion ", stringify!($x), " failed" $(, ": ", $message)?))
            }
        };
    }
}

/// Derives `From<core::convert::Infallible>` for the given type.
///
/// Supports types with arbitrary combinations of lifetimes and type parameters.
///
/// Note: Paths are not supported (for ex. impl_from_infallible!(Hello<D: std::fmt::Display>).
///
/// # Examples
///
/// ```rust
/// # #[allow(unused)]
/// # fn main() {
/// # use core::fmt::{Display, Debug};
/// use bitcoin_internals::impl_from_infallible;
///
/// enum AlphaEnum { Item }
/// impl_from_infallible!(AlphaEnum);
///
/// enum BetaEnum<'b> { Item(&'b usize) }
/// impl_from_infallible!(BetaEnum<'b>);
///
/// enum GammaEnum<T> { Item(T) }
/// impl_from_infallible!(GammaEnum<T>);
///
/// enum DeltaEnum<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a> {
///     Item((&'b usize, &'a usize, T, D))
/// }
/// impl_from_infallible!(DeltaEnum<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a>);
///
/// struct AlphaStruct;
/// impl_from_infallible!(AlphaStruct);
///
/// struct BetaStruct<'b>(&'b usize);
/// impl_from_infallible!(BetaStruct<'b>);
///
/// struct GammaStruct<T>(T);
/// impl_from_infallible!(GammaStruct<T>);
///
/// struct DeltaStruct<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a> {
///     hello: &'a T,
///     what: &'b D,
/// }
/// impl_from_infallible!(DeltaStruct<'b, 'a: 'static + 'b, T: 'a, D: Debug + Display + 'a>);
/// # }
/// ```
///
/// See <https://stackoverflow.com/a/61189128> for more information about this macro.
#[macro_export]
macro_rules! impl_from_infallible {
    ( $name:ident $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)? ) => {
        impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
            From<core::convert::Infallible>
        for $name
            $(< $( $lt ),+ >)?
        {
            fn from(never: core::convert::Infallible) -> Self { match never {} }
        }
    }
}

/// Adds an implementation of `pub fn to_hex(&self) -> String` if `alloc` feature is enabled.
///
/// The added function allocates a `String` then calls through to [`core::fmt::LowerHex`].
///
/// Note: Calling this macro assumes that the calling crate has an `alloc` feature that also activates the
/// `alloc` crate. Calling this macro without the `alloc` feature enabled is a no-op.
#[macro_export]
macro_rules! impl_to_hex_from_lower_hex {
    ($t:ident, $hex_len_fn:expr) => {
        impl $t {
            /// Gets the hex representation of this type
            #[cfg(feature = "alloc")]
            pub fn to_hex(&self) -> alloc::string::String {
                use core::fmt::Write;

                let mut hex_string = alloc::string::String::with_capacity($hex_len_fn(self));
                write!(&mut hex_string, "{:x}", self).expect("writing to string shouldn't fail");

                hex_string
            }
        }
    };
}
