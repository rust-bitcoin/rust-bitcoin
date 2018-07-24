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

            #[inline]
            /// Returns the underlying data.
            pub fn data(&self) -> [$ty; $len] { self.0.clone() }
        }

        impl<'a> From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
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
                        let mut ret: [$ty; $len] = [0; $len];
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

#[cfg(test)]
macro_rules! hex_script (($s:expr) => (::blockdata::script::Script::from(decode($s).unwrap())));

#[cfg(test)]
macro_rules! hex_hash (($s:expr) => (::util::hash::Sha256dHash::from(&decode($s).unwrap()[..])));


// Macros to replace serde's codegen while that is not stable
// Taken from rust-jsonrpc 8a50735712cb7870990314cc150ab9c2955dbfd5

#[macro_export]
macro_rules! __rust_jsonrpc_internal__define_anything_type {
    () => (
        struct Anything;
        struct AnythingVisitor;
        impl ::serde::de::Visitor for AnythingVisitor {
            type Value = Anything;

            fn visit_bool<E>(&mut self, _: bool) -> Result<Anything, E> { Ok(Anything) }
            fn visit_i64<E>(&mut self, _: i64) -> Result<Anything, E> { Ok(Anything) }
            fn visit_u64<E>(&mut self, _: u64) -> Result<Anything, E> { Ok(Anything) }
            fn visit_f64<E>(&mut self, _: f64) -> Result<Anything, E> { Ok(Anything) }
            fn visit_str<E>(&mut self, _: &str) -> Result<Anything, E> { Ok(Anything) }
            fn visit_string<E>(&mut self, _: String) -> Result<Anything, E> { Ok(Anything) }
            fn visit_unit<E>(&mut self) -> Result<Anything, E> { Ok(Anything) }
            fn visit_none<E>(&mut self) -> Result<Anything, E> { Ok(Anything) }

            fn visit_some<D: ::serde::de::Deserializer>(&mut self, d: &mut D) -> Result<Anything, D::Error> {
                serde::de::Deserialize::deserialize(d)
            }

            fn visit_seq<V: ::serde::de::SeqVisitor>(&mut self, v: V) -> Result<Anything, V::Error> {
                let _: Vec<Anything> = try!(::serde::de::impls::VecVisitor::new().visit_seq(v));
                Ok(Anything)
            }

            fn visit_map<V: ::serde::de::MapVisitor>(&mut self, mut v: V) -> Result<Anything, V::Error> {
                while let Some((Anything, Anything)) = try!(v.visit()) { }
                try!(v.end());
                Ok(Anything)
            }
        }

        impl ::serde::Deserialize for Anything {
            fn deserialize<D>(deserializer: &mut D) -> Result<Anything, D::Error>
                where D: ::serde::de::Deserializer
            {
                deserializer.visit(AnythingVisitor)
            }
        }
    )
}

#[macro_export]
macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident $(<- $alt:expr)*),*) => (
        impl ::serde::Deserialize for $name {
            fn deserialize<D>(deserializer: &mut D) -> Result<$name, D::Error>
                where D: serde::de::Deserializer
            {
                // begin type defs
                __rust_jsonrpc_internal__define_anything_type!();

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl ::serde::de::Visitor for EnumVisitor {
                    type Value = Enum;

                    fn visit_str<E>(&mut self, value: &str) -> Result<Enum, E>
                        where E: ::serde::de::Error
                    {
                        match value {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            $(, $alt => Ok(Enum::$fe))*
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl ::serde::Deserialize for Enum {
                    fn deserialize<D>(deserializer: &mut D) -> Result<Enum, D::Error>
                        where D: ::serde::de::Deserializer
                    {
                        deserializer.visit_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl ::serde::de::Visitor for Visitor {
                    type Value = $name;

                    fn visit_map<V>(&mut self, mut v: V) -> Result<$name, V::Error>
                        where V: ::serde::de::MapVisitor
                    {
                        $(let mut $fe = None;)*

                        loop {
                            match try!(v.visit_key()) {
                                Some(Enum::Unknown__Field) => { let _: Anything = try!(v.visit_value()); }
                                $(Some(Enum::$fe) => { $fe = Some(try!(v.visit_value())); })*
                                None => { break; }
                            }
                        }

                        $(let $fe = match $fe {
                            Some(x) => x,
                            None => try!(v.missing_field(stringify!($fe))),
                        };)*
                        try!(v.end());
                        Ok($name{ $($fe: $fe),* })
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.visit_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
                where S: ::serde::Serializer
            {
                // begin type defs
                #[repr(u16)]
                #[derive(Copy, Clone)]
                #[allow(non_camel_case_types)]
                #[allow(dead_code)]
                enum State { $($fe),* , Finished }

                struct MapVisitor<'a> {
                    value: &'a $name,
                    state: State,
                }

                impl<'a> ::serde::ser::MapVisitor for MapVisitor<'a> {
                    fn visit<S>(&mut self, serializer: &mut S) -> Result<Option<()>, S::Error>
                        where S: ::serde::Serializer
                    {
                        match self.state {
                            $(State::$fe => {
                                self.state = unsafe { ::std::mem::transmute(self.state as u16 + 1) };
                                // Use the last alternate name for serialization; in the common case
                                // with zero or one alternates this does the RIght Thing
                                let names = [stringify!($fe), $($alt),*];
                                Ok(Some(try!(serializer.visit_struct_elt(names[names.len() - 1], &self.value.$fe))))
                            })*
                            State::Finished => {
                                Ok(None)
                            }
                        }
                    }
                }
                // end type defs

                serializer.visit_struct(stringify!($name), MapVisitor {
                    value: self,
                    state: unsafe { ::std::mem::transmute(0u16) },
                })
            }
        }
    )
}

#[macro_export]
macro_rules! serde_struct_enum_impl {
    ($name:ident,
     $($varname:ident, $structname:ident, $($fe:ident $(<- $alt:expr)*),*);*
    ) => (
        impl ::serde::Deserialize for $name {
            fn deserialize<D>(deserializer: &mut D) -> Result<$name, D::Error>
                where D: serde::de::Deserializer
            {
                // start type defs
                __rust_jsonrpc_internal__define_anything_type!();

                $(#[allow(non_camel_case_types)] enum $varname { $($fe),* })*
                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($varname($varname)),* }

                struct EnumVisitor;
                impl ::serde::de::Visitor for EnumVisitor {
                    type Value = Enum;

                    fn visit_str<E>(&mut self, value: &str) -> Result<Enum, E>
                        where E: ::serde::de::Error
                    {
                        $($(
                        if value == stringify!($fe) $(|| value == $alt)* {
                            Ok(Enum::$varname($varname::$fe))
                        } else)*)* {
                            Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl ::serde::Deserialize for Enum {
                    fn deserialize<D>(deserializer: &mut D) -> Result<Enum, D::Error>
                        where D: ::serde::de::Deserializer
                    {
                        deserializer.visit_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl ::serde::de::Visitor for Visitor {
                    type Value = $name;

                    #[allow(non_snake_case)] //for $structname
                    #[allow(unused_assignments)] // for `$fe = None` hack
                    fn visit_map<V>(&mut self, mut v: V) -> Result<$name, V::Error>
                        where V: ::serde::de::MapVisitor
                    {
                        $(
                        $(let mut $fe = None;)*
                        // In case of multiple variants having the same field, some of
                        // the above lets will get shadowed. We therefore need to tell
                        // rustc its type, since it otherwise cannot infer it, causing
                        // a compilation error. Hence this hack, which the denizens of
                        // #rust and I had a good laugh over:
                        if false { let _ = $structname { $($fe: $fe.unwrap()),* }; }
                        // The above expression moved $fe so we have to reassign it :)
                        $($fe = None;)*
                        )*

                        loop {
                            match try!(v.visit_key()) {
                                Some(Enum::Unknown__Field) => { let _: Anything = try!(v.visit_value()); }
                                $($(Some(Enum::$varname($varname::$fe)) => {
                                    $fe = Some(try!(v.visit_value())); })*)*
                                None => { break; }
                            }
                        }

                        // try to find a variant for which we have all fields
                        $(
                            let mut $structname = true;
                            $(if $fe.is_none() { $structname = false })*
                            // if we found one, success. extra fields is not an error,
                            // it'd be too much of a PITA to manage overlapping field
                            // sets otherwise.
                            if $structname {
                                $(let $fe = $fe.unwrap();)*
                                try!(v.end());
                                return Ok($name::$varname($structname { $($fe: $fe),* }))
                            }
                        )*
                        // If we get here we failed
                        Err(::serde::de::Error::syntax("did not get all fields"))
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$($(stringify!($fe)),*),*];

                deserializer.visit_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        // impl Serialize (and Deserialize, tho we don't need it) for the underlying structs
        $( serde_struct_impl!($structname, $($fe $(<- $alt)*),*); )*
        // call serialize on the right one
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
                where S: ::serde::Serializer
            {
                match *self {
                    $($name::$varname(ref x) => x.serialize(serializer)),*
                }
            }
        }
    )
}

#[cfg(test)]
mod tests {
    use serde;

    pub struct Variant1 {
        success: bool,
        success_message: String
    }

    pub struct Variant2 {
        success: bool,
        errors: Vec<String>
    }

    pub enum Reply {
        Good(Variant1),
        Bad(Variant2),
    }
    serde_struct_enum_impl!(Reply,
        Good, Variant1, success, success_message;
        Bad, Variant2, success, errors
    );
}


