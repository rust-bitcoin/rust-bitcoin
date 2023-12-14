//! Contains tools (workarounds) to make implementing `const fn`s easier.

/// Copies first `$len` bytes from `$slice` and returns them as an array.
///
/// Returns `None` if `$len > $slice.len()`. `$len` must be (obviously) statically known.
/// Calling from non-const context doesn't affect performance.
#[macro_export]
macro_rules! copy_byte_array_from_slice {
    ($slice:expr, $len:expr) => {
        if $len > $slice.len() {
            None
        } else {
            let mut array = [0u8; $len];
            // Note: produces same assemble as copy_from_slice
            let mut i = 0;
            while i < $len {
                array[i] = $slice[i];
                i += 1;
            }
            Some(array)
        }
    };
}
pub use copy_byte_array_from_slice;

/// Concatenates two byte slices or byte arrays (or combination) to a single array.
///
/// # Panics
///
/// This macro panics if `$len` is not equal to the sum of `$a.len()` and `$b.len()`.
#[macro_export]
macro_rules! concat_bytes_to_arr {
    ($a:expr, $b:expr, $len:expr) => {{
        // avoid repeated eval
        let a = $a;
        let b = $b;

        #[allow(unconditional_panic)]
        let _ = [(); 1][($len != a.len() + b.len()) as usize];

        let mut output = [0u8; $len];
        let mut i = 0;
        while i < a.len() {
            output[i] = $a[i];
            i += 1;
        }
        while i < a.len() + b.len() {
            output[i] = b[i - a.len()];
            i += 1;
        }
        output
    }};
}
pub use concat_bytes_to_arr;

#[macro_export]
/// Enables const fn in specified Rust version
macro_rules! cond_const {
    ($($(#[$attr:meta])* $vis:vis const(in $ver:ident $(= $human_ver:literal)?) fn $name:ident$(<$($gen:tt)*>)?($($args:tt)*) $(-> $ret:ty)? $body:block)+ ) => {
        $(
            #[cfg($ver)]
            $(#[$attr])*
            $(
                #[doc = "\nNote: the function is only `const` in Rust "]
                #[doc = $human_ver]
                #[doc = "."]
            )?
            $vis const fn $name$(<$($gen)*>)?($($args)*) $(-> $ret)? $body

            #[cfg(not($ver))]
            $(#[$attr])*
            $vis fn $name$(<$($gen)*>)?($($args)*) $(-> $ret)? $body
        )+
    };
    ($($(#[$attr:meta])* $vis:vis const(in $ver:ident $(= $human_ver:literal)?) unsafe fn $name:ident$(<$($gen:tt)*>)?($($args:tt)*) $(-> $ret:ty)? $body:block)+ ) => {
        $(
            #[cfg($ver)]
            $(#[$attr])*
            $(
                #[doc = "\nNote: the function is only `const` in Rust "]
                #[doc = $human_ver]
                #[doc = " and newer."]
            )?
            $vis const unsafe fn $name$(<$($gen)*>)?($($args)*) $(-> $ret)? $body

            #[cfg(not($ver))]
            $(#[$attr])*
            $vis unsafe fn $name$(<$($gen)*>)?($($args)*) $(-> $ret)? $body
        )+
    };
}
pub use cond_const;
