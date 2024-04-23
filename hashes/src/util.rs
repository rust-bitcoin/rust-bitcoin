// SPDX-License-Identifier: CC0-1.0

#[macro_export]
/// Adds hexadecimal formatting implementation of a trait `$imp` to a given type `$ty`.
macro_rules! hex_fmt_impl(
    ($reverse:expr, $len:expr, $ty:ident) => (
        $crate::hex_fmt_impl!($reverse, $len, $ty, );
    );
    ($reverse:expr, $len:expr, $ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self).iter().rev(), $crate::hex::Case::Lower)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self), $crate::hex::Case::Lower)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                if $reverse {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self).iter().rev(), $crate::hex::Case::Upper)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $len, <Self as $crate::Hash>::as_byte_array(&self), $crate::hex::Case::Upper)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(&self, f)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{}", self)
            }
        }
    );
);

/// Adds slicing traits implementations to a given type `$ty`
#[macro_export]
macro_rules! borrow_slice_impl(
    ($ty:ident) => (
        $crate::borrow_slice_impl!($ty, );
    );
    ($ty:ident, $($gen:ident: $gent:ident),*) => (
        impl<$($gen: $gent),*> $crate::_export::_core::borrow::Borrow<[u8]> for $ty<$($gen),*>  {
            fn borrow(&self) -> &[u8] {
                &self[..]
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*>  {
            fn as_ref(&self) -> &[u8] {
                &self[..]
            }
        }
    )
);

macro_rules! engine_input_impl(
    () => (
        #[cfg(not(hashes_fuzz))]
        fn input(&mut self, mut inp: &[u8]) {
            while !inp.is_empty() {
                let buf_idx = self.length % <Self as crate::HashEngine>::BLOCK_SIZE;
                let rem_len = <Self as crate::HashEngine>::BLOCK_SIZE - buf_idx;
                let write_len = cmp::min(rem_len, inp.len());

                self.buffer[buf_idx..buf_idx + write_len]
                    .copy_from_slice(&inp[..write_len]);
                self.length += write_len;
                if self.length % <Self as crate::HashEngine>::BLOCK_SIZE == 0 {
                    self.process_block();
                }
                inp = &inp[write_len..];
            }
        }

        #[cfg(hashes_fuzz)]
        fn input(&mut self, inp: &[u8]) {
            for c in inp {
                self.buffer[0] ^= *c;
            }
            self.length += inp.len();
        }
    )
);

// Extracts `hash_newtype(forward)` and `hash_newtype(backward)` attributes if any and turns them
// into bool, defaulting to `DISPLAY_BACKWARD` of the wrapped type if the attribute is omitted.
//
// Once an appropriate attribute is found we pass the remaining ones into another macro to detect
// duplicates/conflicts and report an error.
//
// FYI, no, we can't use a helper macro to first filter all `hash_newtype` attributes. We would be
// attempting to match on macros instead. So we must write `hashe_newtype` in each branch.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_get_direction {
    ($hash:ty, ) => { <$hash as $crate::Hash>::DISPLAY_BACKWARD };
    ($hash:ty, #[hash_newtype(forward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(forward, $($others)*); false } };
    ($hash:ty, #[hash_newtype(backward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(backward, $($others)*); true } };
    ($hash:ty, #[$($ignore:tt)*]  $($others:tt)*) => { $crate::hash_newtype_get_direction!($hash, $($others)*) };
}

// Reports an error if any of the attributes is `hash_newtype($direction)`.
//
// This is used for detection of duplicates/conflicts, see the macro above.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_forbid_direction {
    ($direction:ident, ) => {};
    ($direction:ident, #[hash_newtype(forward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to forward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[hash_newtype(backward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to backward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[$($ignore:tt)*] $(#[$others:tt])*) => {
        $crate::hash_newtype_forbid_direction!($direction, $(#[$others])*)
    };
}

// Checks (at compile time) that all `hash_newtype` attributes are known.
//
// An unknown attribute could be a typo that could cause problems - e.g. wrong display direction if
// it's missing. To prevent this, we call this macro above. The macro produces nothing unless an
// unknown attribute is found in which case it produces `compile_error!`.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_known_attrs {
    (#[hash_newtype(forward)]) => {};
    (#[hash_newtype(backward)]) => {};
    (#[hash_newtype($($unknown:tt)*)]) => { compile_error!(concat!("Unrecognized attribute ", stringify!($($unknown)*))); };
    ($($ignore:tt)*) => {};
}

#[cfg(test)]
mod test {
    use crate::{sha256, Hash};

    #[test]
    fn hash_as_ref_array() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8; 32]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    #[test]
    fn hash_as_ref_slice() {
        let hash = sha256::Hash::hash(&[3, 50]);
        let r = AsRef::<[u8]>::as_ref(&hash);
        assert_eq!(r, hash.as_byte_array());
    }

    #[test]
    fn hash_borrow() {
        use core::borrow::Borrow;

        let hash = sha256::Hash::hash(&[3, 50]);
        let borrowed: &[u8] = hash.borrow();
        assert_eq!(borrowed, hash.as_byte_array());
    }
}
