// SPDX-License-Identifier: CC0-1.0

//! Various macros used by the Rust Bitcoin ecosystem.

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
            pub fn to_hex(&self) -> alloc::string::String {
                use core::fmt::Write;

                let mut hex_string = alloc::string::String::with_capacity($hex_len_fn(self));
                write!(&mut hex_string, "{:x}", self).expect("writing to string shouldn't fail");

                hex_string
            }
        }
    };
}
