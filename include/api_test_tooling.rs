// SPDX-License-Identifier: CC0-1.0

// Asserts that a type does or does not implement a trait, for the `tests/api.rs` of each crate.
//
// Uses autoref specialization, see
// <https://github.com/dtolnay/case-studies/blob/master/autoref-specialization/README.md>.

#[allow(dead_code)]
mod trait_probe {
    use core::marker::PhantomData;

    pub struct Probe<T, M>(pub PhantomData<(T, M)>);

    /// Answers `false` for every probe.
    pub trait Fallback {
        fn is_implemented(&self) -> bool { false }
    }

    impl<T, M> Fallback for Probe<T, M> {}

    /// Answers `true` when `T` implements the marked trait.
    pub trait Specialized {
        fn is_implemented(&self) -> bool;
    }

    macro_rules! probed_traits {
        ($($(#[$attr:meta])* $trait_name:ident => ($($bound:tt)+)),+ $(,)?) => {
            pub mod markers {
                $($(#[$attr])* pub struct $trait_name;)+
            }

            $($(#[$attr])* impl<T: $($bound)+> Specialized for &Probe<T, markers::$trait_name> {
                fn is_implemented(&self) -> bool { true }
            })+
        };
    }

    // A trait must be listed here to be checked.
    // At the present, only units-related traits are listed here.
    probed_traits! {
        #[cfg(feature = "arbitrary")]
        Arbitrary => (for<'a> ::arbitrary::Arbitrary<'a>),
        Clone => (::core::clone::Clone),
        Copy => (::core::marker::Copy),
        Debug => (::core::fmt::Debug),
        Default => (::core::default::Default),
        #[cfg(feature = "serde")]
        Deserialize => (for<'de> ::serde::Deserialize<'de>),
        Display => (::core::fmt::Display),
        Eq => (::core::cmp::Eq),
        Hash => (::core::hash::Hash),
        Ord => (::core::cmp::Ord),
        PartialEq => (::core::cmp::PartialEq),
        PartialOrd => (::core::cmp::PartialOrd),
        Send => (::core::marker::Send),
        #[cfg(feature = "serde")]
        Serialize => (::serde::Serialize),
        Sync => (::core::marker::Sync),
    }
}

/// Asserts that `$type` implements each trait if `$want`, and none of them otherwise.
#[allow(unused_macros)]
macro_rules! assert_trait_impls {
    ($type:ty, [$($trait_name:ident),+ $(,)?], $want:expr) => {{
        #[allow(unused_imports)]
        use $crate::trait_probe::{Fallback as _, Specialized as _};
        $({
            let probe = $crate::trait_probe::Probe::<$type, $crate::trait_probe::markers::$trait_name>(
                core::marker::PhantomData,
            );
            // `&&` makes `Specialized` win when it applies.
            let got = (&&probe).is_implemented();
            assert!(
                got == $want,
                "{} implements {}: got {}, want {}",
                stringify!($type),
                stringify!($trait_name),
                got,
                $want
            );
        })+
    }};
}

/// Asserts that each type implements every trait.
#[allow(unused_macros)]
macro_rules! assert_implements {
    ([$($type:ty),+ $(,)?], $traits:tt) => {
        $(assert_trait_impls!($type, $traits, true);)+
    };
    ($type:ty, $traits:tt) => {
        assert_trait_impls!($type, $traits, true)
    };
}

/// Asserts that each type implements none of the traits.
#[allow(unused_macros)]
macro_rules! assert_does_not_implement {
    ([$($type:ty),+ $(,)?], $traits:tt) => {
        $(assert_trait_impls!($type, $traits, false);)+
    };
    ($type:ty, $traits:tt) => {
        assert_trait_impls!($type, $traits, false)
    };
}
