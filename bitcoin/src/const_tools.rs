// SPDX-License-Identifier: CC0-1.0

//! Contains tools (workarounds) to make implementing `const fn`s easier.

/// Enables const fn in specified Rust version.
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
pub(crate) use cond_const;
