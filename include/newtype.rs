// SPDX-License-Identifier: CC0-1.0

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
        crate::_check_tts_eq!($newtype2, $newtype, "the type name in the impl block doesn't match the struct name");
        $(
            // WARNING: renaming has to be disabled for soundness!
            // If it weren't it'd be possible to make the type inside struct not match the one passed
            // to functions. In principle we could also omit the generics but that'd be confusing for
            // readers.
            crate::_check_tts_eq!($gen2, $gen, "the name of the left generic parameter in impl block doesn't match the one on struct");
            crate::_check_tts_eq!($gen3, $gen, "the name of the right generic parameter in impl block doesn't match the one on struct");
        )?
        $(#[$($struct_attr)*])*
        #[repr(transparent)]
        $vis struct $newtype$(<$gen $(= $default)?>)?($($fields)+) $(where $($where_ty: $bound),*)?;

        impl$(<$gen2>)? $newtype$(<$gen3>)? $(where $($where_ty: $bound),*)? {
            crate::_transparent_ref_conversions! {
                crate::_transparent_newtype_inner_type!($($fields)+);
                $(
                    $(#[$($fn_attr)*])*
                    $fn_vis fn $fn($fn_arg_name: $($fn_arg_ty)+) -> $fn_ret_ty;
                )+
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use transparent_newtype;

macro_rules! _transparent_ref_conversions {
    (
        $inner:ty;
        $(
            $(#[$($fn_attr:tt)*])*
            $fn_vis:vis $(const)? fn $fn:ident($fn_arg_name:ident: $($fn_arg_ty:tt)+) -> $fn_ret_ty:ty;
        )+
    ) => {
        $(
            crate::_transparent_ref_conversion! {
                $inner;
                $(#[$($fn_attr)*])*
                $fn_vis fn $fn($fn_arg_name: $($fn_arg_ty)+) -> $fn_ret_ty;
            }
        )+
    }
}
pub(crate) use _transparent_ref_conversions;

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
        internals::_emit_alloc! {
            $(#[$($from_box_attr)*])*
            #[inline]
            $from_box_vis fn $from_box($from_box_arg_name: alloc::boxed::Box<$inner>) -> alloc::boxed::Box<Self> {
                let ptr = alloc::boxed::Box::into_raw($from_box_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { alloc::boxed::Box::from_raw(ptr as *mut Self) }
            }
        }
    };

    (
        $inner:ty;
        $(#[$($from_rc_attr:tt)*])*
        $from_rc_vis:vis fn $from_rc:ident($from_rc_arg_name:ident: Rc<_>) -> $fn_ret_ty:ty;
    ) => {
        internals::_emit_alloc! {
            $(#[$($from_rc_attr)*])*
            #[inline]
            $from_rc_vis fn $from_rc($from_rc_arg_name: alloc::rc::Rc<$inner>) -> alloc::rc::Rc<Self> {
                let ptr = alloc::rc::Rc::into_raw($from_rc_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { alloc::rc::Rc::from_raw(ptr as *mut Self) }
            }
        }
    };

    (
        $inner:ty;
        $(#[$($from_arc_attr:tt)*])*
        $from_arc_vis:vis fn $from_arc:ident($from_arc_arg_name:ident: Arc<_>) -> $fn_ret_ty:ty;
    ) => {
        internals::_emit_alloc! {
            $(#[$($from_arc_attr)*])*
            #[cfg(target_has_atomic = "ptr")]
            #[inline]
            $from_arc_vis fn $from_arc($from_arc_arg_name: alloc::sync::Arc<$inner>) -> alloc::sync::Arc<Self> {
                let ptr = alloc::sync::Arc::into_raw($from_arc_arg_name);
                // SAFETY: the pointer is created by casting a pointer that is pointing to an object
                // with the same layout and validity invariants and the previous pointer was created
                // directly from box. (Notice repr(transparent).)
                unsafe { alloc::sync::Arc::from_raw(ptr as *mut Self) }
            }
        }
    }
}
pub(crate) use _transparent_ref_conversion;

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
pub(crate) use _check_tts_eq;

macro_rules! _transparent_newtype_inner_type {
    ($(#[$($field_attr:tt)*])* $inner:ty) => {
        $inner
    };
    ($(#[$($phantom_attr:tt)*])* PhantomData<$phantom:ty>, $(#[$($field_attr:tt)*])* $inner:ty) => {
        $inner
    };
}
pub(crate) use _transparent_newtype_inner_type;
