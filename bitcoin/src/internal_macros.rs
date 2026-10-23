// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.

// Keep caller-facing attributes on the trait declaration.
macro_rules! trait_method_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::trait_method_attrs!({ $($all_attrs)* }, { #[doc = $($doc)*] $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::trait_method_attrs!({ $($all_attrs)* }, { #[doc($($doc)*)] $($fun)* });
    };
    ({#[deprecated $($deprecated:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::trait_method_attrs!({ $($all_attrs)* }, { #[deprecated $($deprecated)*] $($fun)* });
    };
    ({#[must_use $($must_use:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::trait_method_attrs!({ $($all_attrs)* }, { #[must_use $($must_use)*] $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::trait_method_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
}
pub(crate) use trait_method_attrs;

// Keep implementation attributes, excluding those only meaningful on the declaration.
macro_rules! impl_method_attrs {
    ({}, {$($fun:tt)*}) => {
        $($fun)*
    };
    ({#[doc = $($doc:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::impl_method_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[doc($($doc:tt)*)] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::impl_method_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[deprecated $($deprecated:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::impl_method_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[must_use $($must_use:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::impl_method_attrs!({ $($all_attrs)* }, { $($fun)* });
    };
    ({#[$($other:tt)*] $($all_attrs:tt)*}, {$($fun:tt)*}) => {
        $crate::internal_macros::impl_method_attrs!({ $($all_attrs)* }, { #[$($other)*] $($fun)* });
    };
}
pub(crate) use impl_method_attrs;

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
                $crate::internal_macros::trait_method_attrs! {
                    { $(#[$($fn_attrs)*])* },
                    {
                        fn $fn$(<$($gen: $gent),*>)?($($params)*) $( -> $ret)? $(where $wherety $(= $whereeq)? $(: $wherebound)?)?;
                    }
                }
            )*
        }

        impl$(<$implgen $(= $impldefault)?>)? $trait_name$(<$traitgen $(= $traitdefault)?>)? for $ty$(<$tygen $(= $tydefault)?>)? {
            $(
                $crate::internal_macros::impl_method_attrs! {
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

#[cfg(test)]
mod tests {
    #![deny(unused_attributes, unused_variables)]

    mod sealed {
        pub trait Sealed {}
        impl Sealed for u8 {}
    }

    crate::internal_macros::define_extension_trait! {
        /// Exercises declaration and implementation attributes in different orders.
        pub trait ExampleExt impl for u8 {
            /// Documentation before deprecation.
            #[deprecated(since = "TBD", note = "use replacement() instead")]
            fn doc_first(&self) -> u8 { *self }

            #[inline]
            #[deprecated(since = "TBD", note = "use replacement() instead")]
            /// Implementation attributes before deprecation.
            #[allow(unused_variables)]
            fn inline_first(&self, unused: u8) -> u8 { *self }

            #[deprecated(since = "TBD", note = "use replacement() instead")]
            #[inline]
            /// Deprecation before implementation attributes.
            #[allow(unused_variables)]
            fn deprecated_first(&self, unused: u8) -> u8 { *self }

            /// A method without deprecation.
            #[must_use]
            fn replacement(&self) -> u8 { *self }
        }
    }

    #[test]
    #[allow(deprecated, deprecated_in_future)] // These calls test the deprecated methods.
    fn method_attributes() {
        assert_eq!(1u8.doc_first(), 1);
        assert_eq!(1u8.inline_first(0), 1);
        assert_eq!(1u8.deprecated_first(0), 1);
        assert_eq!(1u8.replacement(), 1);
    }
}
