// SPDX-License-Identifier: CC0-1.0

//! Various macros used by the Rust Bitcoin ecosystem.

/// Asserts a boolean expression at compile time.
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(; $message:expr)?) => {
        const _: () = {
            if !$x {
                // We can't use formatting in const, only concatenating literals.
                panic!(concat!("assertion ", stringify!($x), " failed" $(, ": ", $message)?))
            }
        };
    }
}
