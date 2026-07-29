// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.

macro_rules! only_doc_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc = $($doc)*] $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc($($doc)*)] $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
}
pub(crate) use only_doc_attrs;

macro_rules! only_non_doc_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[doc = $($doc)*] $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::only_doc_attrs!({ $($all_attrs)* }, { #[$(other)*] $($fun)* });
    };
}
pub(crate) use only_non_doc_attrs;

/// Defines a trait `$trait_name` and implements it for `ty`, used to define extension traits.
macro_rules! define_extension_trait {
    ($(#[$($trait_attrs:tt)*])* $trait_vis:vis trait $trait_name:ident$(<$traitgen:ident $(= $traitdefault:ty)?>)? impl$(<$implgen:ident $(= $impldefault:ty)?>)? for $ty:ident$(<$tygen:ident $(= $tydefault:ty)?>)? {
        $(
            $(#[$($fn_attrs:tt)*])*
            fn $fn:ident$(<$($gen:ident: $gent:path),*>)?($($params:tt)*) $( -> $ret:ty )? $(where $wherety:ident $(= $whereeq:ident)? $(: $wherebound:ident)?)? $body:block
        )*
    }) => {
        #[cfg_attr(docsrs, doc(notable_trait))]
        $(#[$($trait_attrs)*])* $trait_vis trait $trait_name$(<$traitgen $(= $traitdefault)?>)?: sealed::Sealed {
            $(
                $crate::internal_macros::only_doc_attrs! {
                    { $(#[$($fn_attrs)*])* },
                    {
                        fn $fn$(<$($gen: $gent),*>)?($($params)*) $( -> $ret)? $(where $wherety $(= $whereeq)? $(: $wherebound)?)?;
                    }
                }
            )*
        }

        impl$(<$implgen $(= $impldefault)?>)? $trait_name$(<$traitgen $(= $traitdefault)?>)? for $ty$(<$tygen $(= $tydefault)?>)? {
            $(
                $crate::internal_macros::only_non_doc_attrs! {
                    { $(#[$($fn_attrs)*])* },
                    {
                        fn $fn$(<$($gen: $gent),*>)?($($params)*) $( -> $ret )? $(where $wherety $(= $whereeq)? $(: $wherebound)?)? $body
                    }
                }
            )*
        }
    };
}
pub(crate) use define_extension_trait;
