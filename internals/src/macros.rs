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

/// Adds an implementation of `pub fn to_hex(&self) -> String`.
///
/// The added function allocates a `String` then calls through to [`core::fmt::LowerHex`].
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

/// Constructs a transparent wrapper around an inner type and soundly implements reference casts.
///
/// This macro takes care of several issues related to newtypes that need to allow casting their
/// inner types to themselves:
///
/// * It makes sure to put repr(transparent) on the type
/// * It optionally implements conversions from `&`, `&mut`, `Box`, `Rc`, `Arc`
/// * It makes sure to put `#[inline]` on all of these conversions since they are trivial
/// * It makes sure the reference cast is const
/// * It makes sure the `Arc` conversion is conditioned on `target_has_atomic = "ptr"`
///
/// Usage: just type the struct inside the macro as you would implementing it manually except leave
/// `#[repr(transparent)]` out. Then add an impl block for the just-defined type containing function
/// declarations that take a reference/smart pointer to `_` (use literal underscore; e.g. `&_` for
/// shared references) and return `Self` behind the appropriate "pointer" type. Do not write the
/// body, just semicolon.
///
/// The `alloc` types MUST NOT have import paths and don't need imports.
#[macro_export]
macro_rules! transparent_newtype {
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $newtype:tt$(<$gen:ident $(= $default:ty)?>)?($($fields:tt)+) $(where $($where_ty:ty: $bound:path),* $(,)?)?;

        impl$(<$gen2:tt>)? $newtype2:ident$(<$gen3:tt>)? {
            $(
                $(#[$($fn_attr:tt)*])*
                $fn_vis:vis $(const)? fn $fn:ident($fn_arg_name:ident: $($fn_arg_ty:tt)+) -> $fn_ret_ty:ty;
            )*
        }
    ) => {
        $crate::_check_tts_eq!($newtype2, $newtype, "the type name in the impl block doesn't match the struct name");
        $(
            // WARNING: renaming has to be disabled for soundness!
            // If it weren't it'd be possible to make the type inside struct not match the one passed
            // to functions. In principle we could also omit the generics but that'd be confusing for
            // readers.
            $crate::_check_tts_eq!($gen2, $gen, "the name of the left generic parameter in impl block doesn't match the one on struct");
            $crate::_check_tts_eq!($gen3, $gen, "the name of the right generic parameter in impl block doesn't match the one on struct");
        )?
        $(#[$($struct_attr)*])*
        #[repr(transparent)]
        $vis struct $newtype$(<$gen $(= $default)?>)?($($fields)+) $(where $($where_ty: $bound),*)?;

        impl$(<$gen2>)? $newtype$(<$gen3>)? $(where $($where_ty: $bound),*)? {
            $crate::_transparent_ref_conversions! {
                $crate::_transparent_newtype_inner_type!($($fields)+);
                $(
                    $(#[$($fn_attr)*])*
                    $fn_vis fn $fn($fn_arg_name: $($fn_arg_ty)+) -> $fn_ret_ty;
                )+
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! _transparent_ref_conversions {
    (
        $inner:ty;
        $(
            $(#[$($fn_attr:tt)*])*
            $fn_vis:vis $(const)? fn $fn:ident($fn_arg_name:ident: $($fn_arg_ty:tt)+) -> $fn_ret_ty:ty;
        )+
    ) => {
        $(
            $crate::_transparent_ref_conversion! {
                $inner;
                $(#[$($fn_attr)*])*
                $fn_vis fn $fn($fn_arg_name: $($fn_arg_ty)+) -> $fn_ret_ty;
            }
        )+
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! _transparent_ref_conversion {
    (
        $inner:ty;
        $(#[$($from_ref_attr:tt)*])*
        $from_ref_vis:vis fn $from_ref:ident($from_ref_arg_name:ident: &_) -> $fn_ret_ty:ty;
    ) => {
        #[inline]
        $(#[$($from_ref_attr)*])*
        $from_ref_vis const fn $from_ref($from_ref_arg_name: &$inner) -> &Self {
            // SAFETY: the pointer is created by casting a pointer that is pointing to an object
            // with the same layout and validity invariants and the previous pointer was created
            // directly from a reference. (Notice repr(transparent).)
            // The lifetime of the input reference matches the lifetime of the returned reference.
            unsafe { &*($from_ref_arg_name as *const $inner as *const Self) }
        }
    };
    (
        $inner:ty;
        $(#[$($from_mut_attr:tt)*])*
        $from_mut_vis:vis fn $from_mut:ident($from_mut_arg_name:ident: &mut _) -> $fn_ret_ty:ty;
    ) => {
        #[inline]
        $(#[$($from_mut_attr)*])*
        $from_mut_vis fn $from_mut($from_mut_arg_name: &mut $inner) -> &mut Self {
            // SAFETY: the pointer is created by casting a pointer that is pointing to an object
            // with the same layout and validity invariants and the previous pointer was created
            // directly from a reference. (Notice repr(transparent).)
            // The lifetime of the input reference matches the lifetime of the returned reference.
            unsafe { &mut *($from_mut_arg_name as *mut $inner as *mut Self) }
        }
    };
    (
        $inner:ty;
        $(#[$($from_box_attr:tt)*])*
        $from_box_vis:vis fn $from_box:ident($from_box_arg_name:ident: Box<_>) -> $fn_ret_ty:ty;
    ) => {
        $crate::_emit_alloc! {
            $(#[$($from_box_attr)*])*
            #[inline]
            $from_box_vis fn $from_box($from_box_arg_name: $crate::_export::alloc::boxed::Box<$inner>) -> $crate::_export::alloc::boxed::Box<Self> {
                let ptr = $crate::_export::alloc::boxed::Box::into_raw($from_box_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { $crate::_export::alloc::boxed::Box::from_raw(ptr as *mut Self) }
            }
        }
    };

    (
        $inner:ty;
        $(#[$($from_rc_attr:tt)*])*
        $from_rc_vis:vis fn $from_rc:ident($from_rc_arg_name:ident: Rc<_>) -> $fn_ret_ty:ty;
    ) => {
        $crate::_emit_alloc! {
            $(#[$($from_rc_attr)*])*
            #[inline]
            $from_rc_vis fn $from_rc($from_rc_arg_name: $crate::_export::alloc::rc::Rc<$inner>) -> $crate::_export::alloc::rc::Rc<Self> {
                let ptr = $crate::_export::alloc::rc::Rc::into_raw($from_rc_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { $crate::_export::alloc::rc::Rc::from_raw(ptr as *mut Self) }
            }
        }
    };

    (
        $inner:ty;
        $(#[$($from_arc_attr:tt)*])*
        $from_arc_vis:vis fn $from_arc:ident($from_arc_arg_name:ident: Arc<_>) -> $fn_ret_ty:ty;
    ) => {
        $crate::_emit_alloc! {
            $(#[$($from_arc_attr)*])*
            #[cfg(target_has_atomic = "ptr")]
            #[inline]
            $from_arc_vis fn $from_arc($from_arc_arg_name: $crate::_export::alloc::sync::Arc<$inner>) -> $crate::_export::alloc::sync::Arc<Self> {
                let ptr = $crate::_export::alloc::sync::Arc::into_raw($from_arc_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { $crate::_export::alloc::sync::Arc::from_raw(ptr as *mut Self) }
            }
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! _check_tts_eq {
    ($left:tt, $right:tt, $message:literal) => {
        macro_rules! token_eq {
            ($right) => {};
            ($any:tt) => {
                compile_error!($message)
            };
        }
        token_eq!($left);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! _transparent_newtype_inner_type {
    ($(#[$($field_attr:tt)*])* $inner:ty) => {
        $inner
    };
    ($(#[$($phantom_attr:tt)*])* PhantomData<$phantom:ty>, $(#[$($field_attr:tt)*])* $inner:ty) => {
        $inner
    };
}

/// Emits given tokens only if the `alloc` feature **in this crate** is enabled.
///
/// (The feature is currently enabled.)
#[cfg(feature = "alloc")]
#[doc(hidden)]
#[macro_export]
macro_rules! _emit_alloc {
    ($($tokens:tt)*) => { $($tokens)* };
}

/// Emits given tokens only if the `alloc` feature **in this crate** is enabled.
///
/// (The feature is currently disabled.)
#[cfg(not(feature = "alloc"))]
#[doc(hidden)]
#[macro_export]
macro_rules! _emit_alloc {
    ($($tokens:tt)*) => {};
}
