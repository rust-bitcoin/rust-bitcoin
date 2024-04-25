// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).

/// Implements tagged SHA256 hashing for `$hashtype`.
///
/// Usage: `impl_tagged_hashtype!(TapSighash, hash_str("TapSighash"));`
#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype {
    ($(
        $(#[$($type_attrs:tt)*])* $type_vis:vis struct $newtype:ident(sha256::Hash) = $constructor:tt($($tag_value:tt)+);
        $(#[$($engine_attrs:meta)*])* $engine_vis:vis struct $engine:ident(_);
    )+) => {
        $(
        $($crate::hash_newtype_known_attrs!(#[ $($type_attrs)* ]);)*

        $crate::hash_newtype_struct! {
            $type_vis struct $newtype($crate::sha256::Hash);

            $({ $($type_attrs)* })*
        }

        /// Engine to compute tagged SHA2 hash function.
        #[derive(Clone)]
        $engine_vis struct $engine($crate::sha256::HashEngine);

        impl Default for $engine {
            fn default() -> Self {
                const MIDSTATE: (sha256::Midstate, usize) = $crate::tagged_midstate!($constructor, $($tag_value)+);
                #[allow(unused)]
                const _LENGTH_CHECK: () = [(); 1][MIDSTATE.1 % 64];

                Self($crate::sha256::HashEngine::from_midstate(MIDSTATE.0, MIDSTATE.1))
            }
        }

        impl $crate::HashEngine for $engine {
            type MidState = $crate::sha256::Midstate;
            fn midstate(&self) -> Self::MidState { self.0.midstate() }
            const BLOCK_SIZE: usize = $crate::sha256::BLOCK_SIZE;
            fn input(&mut self, data: &[u8]) { self.0.input(data) }
            fn n_bytes_hashed(&self) -> usize { self.0.n_bytes_hashed() }
        }

        $crate::hex_fmt_impl!(<$newtype as $crate::Hash>::DISPLAY_BACKWARD, 32, $newtype);
        $crate::serde_impl!($newtype, 32);
        $crate::borrow_slice_impl!($newtype);

        #[allow(unused)] // Not all functions are used by all hash types.
        impl $newtype {
            /// Creates this wrapper type from the inner hash type.
            pub fn from_raw_hash(inner: $crate::sha256::Hash) -> Self { Self(inner) }

            /// Returns the inner hash (sha256, sh256d etc.).
            pub fn to_raw_hash(self) -> $crate::sha256::Hash { self.0 }

            /// Returns a reference to the inner hash (sha256, sh256d etc.).
            pub fn as_raw_hash(&self) -> &$crate::sha256::Hash { &self.0 }
        }

        impl $crate::Hash for $newtype {
            type Engine = $engine;
            type Bytes = [u8; 32];

            const LEN: usize = 32;
            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($crate::sha256::Hash, $(#[$($type_attrs)*])*);

            fn engine() -> Self::Engine { Default::default() }

            fn from_engine(e: $engine) -> Self {
                Self($crate::sha256::Hash::from_engine(e.0))
            }

            fn from_slice(sl: &[u8]) -> Result<Self, $crate::FromSliceError> {
                Ok(Self($crate::sha256::Hash::from_slice(sl)?))
            }

            fn to_byte_array(self) -> [u8; 32] { self.0.to_byte_array() }

            fn as_byte_array(&self) -> &[u8; 32] { self.0.as_byte_array() }

            fn from_byte_array(bytes: [u8; 32]) -> Self {
                Self($crate::sha256::Hash::from_byte_array(bytes))
            }

            fn all_zeros() -> Self { Self($crate::sha256::Hash::all_zeros()) }

        }

        impl core::str::FromStr for $newtype {
            type Err = hex::HexToArrayError;

            fn from_str(s: &str) -> core::result::Result<$newtype, Self::Err> {
                use $crate::Hash as _;
                use hex::FromHex;

                let mut bytes = <[u8; 32]>::from_hex(s)?;
                if <$newtype as $crate::Hash>::DISPLAY_BACKWARD {
                    bytes.reverse();
                }
                Ok($newtype($crate::sha256::Hash::from_byte_array(bytes)))
            }
        }

        impl core::convert::AsRef<[u8; 32]> for $newtype {
            #[inline]
            fn as_ref(&self) -> &[u8; 32] { AsRef::<[u8; 32]>::as_ref(&self.0) }
        }

        impl<I: core::slice::SliceIndex<[u8]>> core::ops::Index<I> for $newtype {
            type Output = I::Output;
            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
        )+
    };
}

/// Implements `consensus::{Decodable, Encodable}` for `$newtype`.
///
/// Requires the traits to be in scope.
#[rustfmt::skip]
#[doc(hidden)]
#[macro_export]
macro_rules! impl_tagged_newtype_encode {
    ($newtype:ident) => {
        $crate::internal_macros::impl_newtype_encode!($newtype, $crate::sha256::Hash);
    }
}

/// Creates a const midstate used to instantiate a SHA256 pre-tagged engine.
///
/// Requires `hashes::sha256` to be in scope.
#[doc(hidden)]
#[macro_export]
macro_rules! tagged_midstate {
    (hash_str, $value:expr) => {
        (sha256::Midstate::hash_tag($value.as_bytes()), 64)
    };
    (hash_bytes, $value:expr) => {
        (sha256::Midstate::hash_tag($value), 64)
    };
    (raw, $bytes:expr, $len:expr) => {
        (sha256::Midstate::from_byte_array($bytes), $len)
    };
}

/// Implements `io::Write` for `$engine`.
///
/// Requires `bitcoin_io::impl_write!` to be in scope.
#[macro_export]
macro_rules! impl_tagged_engine_write {
    ($engine:ident) => {
        impl_write!(
            $engine,
            |us: &mut $engine, buf| {
                us.input(buf);
                Ok(buf.len())
            },
            |_us| { Ok(()) }
        );
    }
}

/// Implements `schemars::JsonSchema` for `$newtype`.
#[cfg(feature = "schemars")]
#[macro_export]
macro_rules! impl_tagged_newtype_schemars {
    ($newtype:ident) => {
        impl schemars::JsonSchema for $newtype {
            fn schema_name() -> String { stringify!($newtype).to_owned() }

            fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
                schema.string = Some(Box::new(schemars::schema::StringValidation {
                    max_length: Some(32 * 2),
                    min_length: Some(32 * 2),
                    pattern: Some("[0-9a-fA-F]+".to_owned()),
                }));
                schema.into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256;
    #[cfg(feature = "alloc")]
    use crate::Hash as _;

    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    sha256t_hash_newtype! {
        /// A test tagged hash.
        pub struct TestHash(sha256::Hash) = raw(TEST_MIDSTATE, 64);
        pub struct TestHashEngine(_);

        /// A test tagged hash.
        #[hash_newtype(backward)]
        pub struct TestHashBackward(sha256::Hash) = raw(TEST_MIDSTATE, 64);
        pub struct TestHashBackwardEngine(_);

        /// A test tagged hash.
        #[hash_newtype(forward)]
        pub struct TestHashForward(sha256::Hash) = raw(TEST_MIDSTATE, 64);
        pub struct TestHashForwardEngine(_);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sha256t_newtype_display_default() {
        assert_eq!(
            TestHash::hash(&[0]).to_string(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829"
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sha256t_newtype_display_backward() {
        assert_eq!(
            TestHashBackward::hash(&[0]).to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn sha256t_newtype_display_forward() {
        assert_eq!(
            TestHashForward::hash(&[0]).to_string(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829"
        );
    }
}
