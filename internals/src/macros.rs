// SPDX-License-Identifier: CC0-1.0

//! Various macros used by the Rust Bitcoin ecosystem.

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
