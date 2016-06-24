// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl<S: ::network::serialize::SimpleEncoder> ::network::encodable::ConsensusEncodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
                $( try!(self.$field.consensus_encode(s)); )+
                Ok(())
            }
        }

        impl<D: ::network::serialize::SimpleDecoder> ::network::encodable::ConsensusDecodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, D::Error> {
                use network::encodable::ConsensusDecodable;
                Ok($thing {
                    $( $field: try!(ConsensusDecodable::consensus_decode(d)), )+
                })
            }
        }
    );
}

macro_rules! impl_newtype_consensus_encoding {
    ($thing:ident) => (
        impl<S: ::network::serialize::SimpleEncoder> ::network::encodable::ConsensusEncodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
                let &$thing(ref data) = self;
                data.consensus_encode(s)
            }
        }

        impl<D: ::network::serialize::SimpleDecoder> ::network::encodable::ConsensusDecodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, D::Error> {
                Ok($thing(try!(ConsensusDecodable::consensus_decode(d))))
            }
        }
    );
}

macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize { $len }

            #[inline]
            /// Returns whether the object, as an array, is empty. Always false.
            pub fn is_empty(&self) -> bool { false }
        }

        impl<'a> From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                unsafe {
                    use std::intrinsics::copy_nonoverlapping;
                    use std::mem;
                    let mut ret: $thing = mem::uninitialized();
                    copy_nonoverlapping(data.as_ptr(),
                                        ret.as_mut_ptr(),
                                        mem::size_of::<$thing>());
                    ret
                }
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                let &$thing(ref dat) = self;
                &dat[index]
            }
        }

        impl_index_newtype!($thing, $ty);

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        impl Eq for $thing {}

        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> ::std::cmp::Ordering {
                // manually implement comparison to get little-endian ordering
                // (we need this for our numeric types; non-numeric ones shouldn't
                // be ordered anyway except to put them in BTrees or whatever, and
                // they don't care how we order as long as we're consisistent).
                for i in 0..$len {
                    if self[$len - 1 - i] < other[$len - 1 - i] { return ::std::cmp::Ordering::Less; }
                    if self[$len - 1 - i] > other[$len - 1 - i] { return ::std::cmp::Ordering::Greater; }
                }
                ::std::cmp::Ordering::Equal
            }
        }

        #[cfg_attr(feature = "clippy", allow(expl_impl_clone_on_copy))] // we don't define the `struct`, we have to explicitly impl
        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                $thing::from(&self[..])
            }
        }

        impl Copy for $thing {}

        impl ::std::hash::Hash for $thing {
            #[inline]
            fn hash<H>(&self, state: &mut H)
                where H: ::std::hash::Hasher
            {
                (&self[..]).hash(state);
            }

            fn hash_slice<H>(data: &[$thing], state: &mut H)
                where H: ::std::hash::Hasher
            {
                for d in data.iter() {
                    (&d[..]).hash(state);
                }
            }
        }

        impl ::rand::Rand for $thing {
            #[inline]
            fn rand<R: ::rand::Rng>(r: &mut R) -> $thing {
                $thing(::rand::Rand::rand(r))
            }
        }
    }
}

macro_rules! impl_array_newtype_encodable {
    ($thing:ident, $ty:ty, $len:expr) => {

        impl ::serde::Deserialize for $thing {
            fn deserialize<D>(d: &mut D) -> Result<$thing, D::Error>
                where D: ::serde::Deserializer
            {
                // We have to define the Visitor struct inside the function
                // to make it local ... what we really need is that it's
                // local to the macro, but this is Close Enough.
                struct Visitor {
                    marker: ::std::marker::PhantomData<$thing>,
                }
                impl ::serde::de::Visitor for Visitor {
                    type Value = $thing;

                    #[inline]
                    fn visit_seq<V>(&mut self, mut v: V) -> Result<$thing, V::Error>
                        where V: ::serde::de::SeqVisitor
                    {
                        unsafe {
                            use std::mem;
                            let mut ret: [$ty; $len] = mem::uninitialized();
                            for item in ret.iter_mut() {
                                *item = match try!(v.visit()) {
                                    Some(c) => c,
                                    None => return Err(::serde::de::Error::end_of_stream())
                                };
                            }
                            try!(v.end());
                            Ok($thing(ret))
                        }
                    }
                }

                // Begin actual function
                d.visit(Visitor { marker: ::std::marker::PhantomData })
            }
        }

        impl ::serde::Serialize for $thing {
            fn serialize<S>(&self, s: &mut S) -> Result<(), S::Error>
                where S: ::serde::Serializer
            {
                let &$thing(ref dat) = self;
                (&dat[..]).serialize(s)
            }
        }
    }
}

macro_rules! impl_array_newtype_show {
    ($thing:ident) => {
        impl ::std::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, concat!(stringify!($thing), "({:?})"), &self[..])
            }
        }
    }
}

macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }

    }
}

macro_rules! display_from_debug {
    ($thing:ident) => {
        impl ::std::fmt::Display for $thing {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
                ::std::fmt::Debug::fmt(self, f)
            }
        }
    }
}

