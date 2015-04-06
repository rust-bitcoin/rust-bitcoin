// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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
      /// Provides an immutable view into the object
      pub fn as_slice<'a>(&'a self) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.as_slice()
      }

      #[inline]
      /// Provides an immutable view into the object from index `s` inclusive to `e` exclusive
      pub fn slice<'a>(&'a self, s: usize, e: usize) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.slice(s, e)
      }

      #[inline]
      /// Provides an immutable view into the object, up to index `n` exclusive
      pub fn slice_to<'a>(&'a self, n: usize) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.slice_to(n)
      }

      #[inline]
      /// Provides an immutable view into the object, starting from index `n`
      pub fn slice_from<'a>(&'a self, n: usize) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.slice_from(n)
      }

      #[inline]
      /// Converts the object to a raw pointer
      pub fn as_ptr(&self) -> *const $ty {
        let &$thing(ref dat) = self;
        dat.as_ptr()
      }

      #[inline]
      /// Converts the object to a mutable raw pointer
      pub fn as_mut_ptr(&mut self) -> *mut $ty {
        let &$thing(ref mut dat) = self;
        dat.as_mut_ptr()
      }

      #[inline]
      /// Returns the length of the object as an array
      pub fn len(&self) -> usize { $len }

      /// Constructs a new object from raw data
      pub fn from_slice(data: &[$ty]) -> $thing {
        assert_eq!(data.len(), $len);
        unsafe {
          use std::intrinsics::copy_nonoverlapping;
          use std::mem;
          let mut ret: $thing = mem::uninitialized();
          copy_nonoverlapping(ret.as_mut_ptr(),
                              data.as_ptr(),
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

        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[index.start..index.end]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[..index.end]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[index.start..]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                let &$thing(ref dat) = self;
                &dat[..]
            }
        }

    impl PartialEq for $thing {
      #[inline]
      fn eq(&self, other: &$thing) -> bool {
        self.as_slice() == other.as_slice()
      }
    }

    impl Eq for $thing {}

    impl Clone for $thing {
      #[inline]
      fn clone(&self) -> $thing {
        $thing::from_slice(self.as_slice())
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
              for i in 0..$len {
                ret[i] = try!(v.visit());
              }
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
        write!(f, concat!(stringify!($thing), "({})"), self.as_slice())
      }
    }
  }
}

