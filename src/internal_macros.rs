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

