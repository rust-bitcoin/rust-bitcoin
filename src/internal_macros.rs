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

#![macro_escape]

macro_rules! impl_consensus_encoding(
  ($thing:ident, $($field:ident),+) => (
    impl<S: ::network::serialize::SimpleEncoder<E>, E> ::network::encodable::ConsensusEncodable<S, E> for $thing {
      #[inline]
      fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
        $( try!(self.$field.consensus_encode(s)); )+
        Ok(())
      }
    }

    impl<D: ::network::serialize::SimpleDecoder<E>, E> ::network::encodable::ConsensusDecodable<D, E> for $thing {
      #[inline]
      fn consensus_decode(d: &mut D) -> Result<$thing, E> {
        use network::encodable::ConsensusDecodable;
        Ok($thing {
          $( $field: try!(ConsensusDecodable::consensus_decode(d)), )+
        })
      }
    }
  );
)

macro_rules! impl_newtype_consensus_encoding(
  ($thing:ident) => (
    impl<S: ::network::serialize::SimpleEncoder<E>, E> ::network::encodable::ConsensusEncodable<S, E> for $thing {
      #[inline]
      fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
        let &$thing(ref data) = self;
        data.consensus_encode(s)
      }
    }

    impl<D: ::network::serialize::SimpleDecoder<E>, E> ::network::encodable::ConsensusDecodable<D, E> for $thing {
      #[inline]
      fn consensus_decode(d: &mut D) -> Result<$thing, E> {
        Ok($thing(try!(ConsensusDecodable::consensus_decode(d))))
      }
    }
  );
)

macro_rules! impl_json(
  ($thing:ident, $($field:ident),+) => (
    impl ::serialize::json::ToJson for $thing {
      fn to_json(&self) -> ::serialize::json::Json {
        use std::collections::TreeMap;
        use serialize::json::{ToJson, Object};
        let mut ret = TreeMap::new();
        $( ret.insert(stringify!($field).to_string(), self.$field.to_json()); )+
        Object(ret)
      }
    }
  );
)

macro_rules! impl_array_newtype(
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
      pub fn slice<'a>(&'a self, s: uint, e: uint) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.slice(s, e)
      }

      #[inline]
      /// Provides an immutable view into the object, up to index `n` exclusive
      pub fn slice_to<'a>(&'a self, n: uint) -> &'a [$ty] {
        let &$thing(ref dat) = self;
        dat.slice_to(n)
      }

      #[inline]
      /// Provides an immutable view into the object, starting from index `n`
      pub fn slice_from<'a>(&'a self, n: uint) -> &'a [$ty] {
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
      pub fn len(&self) -> uint { $len }

      /// Constructs a new object from raw data
      pub fn from_slice(data: &[$ty]) -> $thing {
        assert_eq!(data.len(), $len);
        unsafe {
          use std::intrinsics::copy_nonoverlapping_memory;
          use std::mem;
          let mut ret: $thing = mem::uninitialized();
          copy_nonoverlapping_memory(ret.as_mut_ptr(),
                                     data.as_ptr(),
                                     mem::size_of::<$thing>());
          ret
        }
      }
    }

    impl Index<uint, $ty> for $thing {
      #[inline]
      fn index<'a>(&'a self, idx: &uint) -> &'a $ty {
        let &$thing(ref data) = self;
        &data[*idx]
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

    impl ::std::fmt::Show for $thing {
      fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, concat!(stringify!($thing), "({})"), self.as_slice())
      }
    }
  }
)

