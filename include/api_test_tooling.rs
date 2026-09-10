// SPDX-License-Identifier: CC0-1.0

// Asserts that a type does or does not implement a trait, for the `tests/api.rs` of each crate.
//
// Uses autoref specialization, see
// <https://github.com/dtolnay/case-studies/blob/master/autoref-specialization/README.md>.
//
// TODO: At the present, this module is only used by the units crate, pending support for other crates.

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
        ($($(#[$attr:meta])* $trait_name:ident => ($($bound:tt)+)),* $(,)?) => {
            pub mod markers {
                $($(#[$attr])* pub struct $trait_name;)*
            }

            $($(#[$attr])* impl<T: $($bound)+> Specialized for &Probe<T, markers::$trait_name> {
                fn is_implemented(&self) -> bool { true }
            })*
        };
    }

    // A trait must be listed here to be checked.
    // At the present, only units traits are expected to get listed here.
    probed_traits! {}
}

/// Asserts that `$type` implements the trait if `$want`, and does not otherwise.
/// Only works on concrete types. Inside a generic function it always answers `false`.
#[allow(unused_macros)]
macro_rules! assert_trait_impls {
    ($type:ty, $trait_name:ident, $want:expr) => {{
        #[allow(unused_imports)]
        use $crate::trait_probe::{Fallback as _, Specialized as _};
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
    }};
}

/// Asserts that each type in a list does or does not implement the trait.
///
/// With `except [..]`, every exception must be in the list and is expected to answer the opposite.
#[allow(unused_macros)]
macro_rules! assert_group {
    // Checks every exception is in the group, then expects the opposite of `$want` for them.
    (@except [$($ty:ty),+ $(,)?], $want:expr, $trait_name:ident, [$($ex:ty),+ $(,)?]) => {{
        // `stringify!` may add spaces inside a type, so compare without spaces.
        let same = |a: &str, b: &str| a.replace(' ', "") == b.replace(' ', "");
        let members = [$(stringify!($ty)),+];
        let exceptions = [$(stringify!($ex)),+];
        for ex in exceptions {
            assert!(members.iter().any(|m| same(m, ex)), "exception {} is not in the group", ex);
        }
        $(assert_trait_impls!(
            $ty,
            $trait_name,
            $want != exceptions.iter().any(|ex| same(ex, stringify!($ty)))
        );)+
    }};
    // Each type implements the trait, and each exception does not.
    ($types:tt, assert_implements, $trait_name:ident, except $except:tt) => {
        assert_group!(@except $types, true, $trait_name, $except)
    };
    // No type implements the trait, and each exception does.
    ($types:tt, assert_does_not_implement, $trait_name:ident, except $except:tt) => {
        assert_group!(@except $types, false, $trait_name, $except)
    };
    // Each type implements the trait.
    ([$($ty:ty),+ $(,)?], assert_implements, $trait_name:ident) => {
        $(assert_trait_impls!($ty, $trait_name, true);)+
    };
    // No type implements the trait.
    ([$($ty:ty),+ $(,)?], assert_does_not_implement, $trait_name:ident) => {
        $(assert_trait_impls!($ty, $trait_name, false);)+
    };
}

/// Generates the macro `$name!`, which turns a group name into its list of types and calls
/// `assert_group!` with it. A `union` is a group made of other groups.
///
/// The first token must be a literal `$`, as in `type_groups! { $ units; ... }`. It is pasted
/// wherever `units!` needs `$` in its own rules, since a `$` written directly would be read by
/// `type_groups!` itself.
#[allow(unused_macros)]
macro_rules! type_groups {
    (
        // A literal `$`, then the name of the macro to generate.
        $d:tt $name:ident;
        // Each group and its types.
        $(group $group:ident = [$($ty:ty),+ $(,)?];)+
        // Each union and the groups it joins.
        $(union $union:ident = $($part:ident)|+;)*
    ) => {
        macro_rules! $name {
            // Every group name is resolved, hand the collected types to `assert_group!`.
            (@collect [] [$d($d ty:tt)*] $d($d rest:tt)*) => {
                assert_group!([$d($d ty)*] $d($d rest)*)
            };
            // Resolve the next name still to do.
            (@collect [$d next:ident $d($d names:ident)*] $d types:tt $d($d rest:tt)*) => {
                $name!(@resolve $d next [$d($d names)*] $d types $d($d rest)*)
            };
            // A group adds its types.
            $((@resolve $group [$d($d names:ident)*] [$d($d types:tt)*] $d($d rest:tt)*) => {
                $name!(@collect [$d($d names)*] [$d($d types)* $($ty,)+] $d($d rest)*)
            };)+
            // A union queues the groups it joins.
            $((@resolve $union [$d($d names:ident)*] $d types:tt $d($d rest:tt)*) => {
                $name!(@collect [$($part)+ $d($d names)*] $d types $d($d rest)*)
            };)*
            // An explicit list of types.
            ([$d($d ty:tt)*], $d($d rest:tt)*) => {
                assert_group!([$d($d ty)*], $d($d rest)*)
            };
            // A group name, start resolving it.
            ($d group:ident, $d($d rest:tt)*) => {
                $name!(@collect [$d group] [] , $d($d rest)*)
            };
        }
    };
}
