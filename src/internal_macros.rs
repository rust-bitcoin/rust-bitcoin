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

macro_rules! impl_serializable(
  ($thing:ident, $($field:ident),+) => (
    impl Serializable for $thing {
      fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        $( ret.extend(self.$field.serialize().move_iter()); )+
        ret
      }

      fn serialize_iter<'a>(&'a self) -> SerializeIter<'a> {
        SerializeIter {
          data_iter: None,
          sub_iter_iter: box vec![ $( &self.$field as &Serializable, )+ ].move_iter(),
          sub_iter: None,
          sub_started: false
        }
      }

      fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<$thing> {
        use util::misc::prepend_err;
        let ret = Ok($thing {
          $( $field: try!(prepend_err(stringify!($field), Serializable::deserialize(iter.by_ref()))), )+
        });
        ret
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

