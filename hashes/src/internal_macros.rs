//! Non-public macros

/// Adds trait impls to the type called `Hash` in the current scope.
///
/// Implpements various conversion traits as well as the [`crate::Hash`] trait.
/// Arguments:
///
/// * `$bits` - number of bits this hash type has
/// * `$reversed` - `bool`  - `true` if the hash type should be displayed backwards, `false`
///    otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s)
///
/// Restrictions on usage:
///
/// * There must be a free-standing `fn from_engine(HashEngine) -> Hash` in the scope
/// * `fn internal_new([u8; $bits / 8]) -> Self` must exist on `Hash`
/// * `fn internal_engine() -> HashEngine` must exist on `Hash`
///
/// `from_engine` obviously implements the finalization algorithm.
/// `internal_new` is required so that types with more than one field are constructible.
/// `internal_engine` is required to initialize the engine for given hash type.
macro_rules! hash_trait_impls {
    ($bits:expr, $reversed:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> str::FromStr for Hash<$($gen),*> {
            type Err = hex::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                hex::FromHex::from_hex(s)
            }
        }

        hex_fmt_impl!(Hash $(, $gen: $gent)*);
        serde_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
        borrow_slice_impl!(Hash $(, $gen: $gent)*);

        impl<I: SliceIndex<[u8]> $(, $gen: $gent)*> Index<I> for Hash<$($gen),*> {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }

        impl<$($gen: $gent),*> crate::Hash for Hash<$($gen),*> {
            type Engine = HashEngine;
            type Inner = [u8; $bits / 8];

            const LEN: usize = $bits / 8;
            const DISPLAY_BACKWARD: bool = $reversed;

            fn engine() -> Self::Engine {
                Self::internal_engine()
            }

            fn from_engine(e: HashEngine) -> Hash<$($gen),*> {
                from_engine(e)
            }

            fn from_slice(sl: &[u8]) -> Result<Hash<$($gen),*>, Error> {
                if sl.len() != $bits / 8 {
                    Err(Error::InvalidLength(Self::LEN, sl.len()))
                } else {
                    let mut ret = [0; $bits / 8];
                    ret.copy_from_slice(sl);
                    Ok(Self::internal_new(ret))
                }
            }

            fn into_inner(self) -> Self::Inner {
                self.0
            }

            fn as_inner(&self) -> &Self::Inner {
                &self.0
            }

            fn from_inner(inner: Self::Inner) -> Self {
                Self::internal_new(inner)
            }

            fn all_zeros() -> Self {
                Hash::internal_new([0x00; $bits / 8])
            }
        }
    }
}
pub(crate) use hash_trait_impls;

/// Creates a type called `Hash` and implements standard interface for it.
///
/// The created type will have all standard derives, `Hash` impl and implementation of
/// `internal_engine` returning default. The created type has a single field.
///
/// Arguments:
///
/// * `$bits` - the number of bits of the hash type
/// * `$reversed` - `true` if the hash should be displayed backwards, `false` otherwise
/// * `$doc` - doc string to put on the type
/// * `$schemars` - a literal that goes into `schema_with`.
///
/// The `from_engine` free-standing function is still required with this macro. See the doc of
/// [`hash_trait_impls`].
macro_rules! hash_type {
    ($bits:expr, $reversed:expr, $doc:literal, $schemars:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "schemars", derive(crate::schemars::JsonSchema))]
        #[repr(transparent)]
        pub struct Hash(
            #[cfg_attr(feature = "schemars", schemars(schema_with = $schemars))]
            [u8; $bits / 8]
        );

        impl Hash {
            fn internal_new(arr: [u8; $bits / 8]) -> Self {
                Hash(arr)
            }

            fn internal_engine() -> HashEngine {
                Default::default()
            }
        }

        crate::internal_macros::hash_trait_impls!($bits, $reversed);
    }
}
pub(crate) use hash_type;
