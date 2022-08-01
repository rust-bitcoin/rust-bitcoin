// SPDX-License-Identifier: CC0-1.0

#[allow(unused_macros)]
macro_rules! hex_psbt {
    ($s:expr) => { $crate::consensus::deserialize::<$crate::util::psbt::PartiallySignedTransaction>(&<$crate::prelude::Vec<u8> as $crate::hashes::hex::FromHex>::from_hex($s).unwrap()) };
}

macro_rules! combine {
    ($thing:ident, $slf:ident, $other:ident) => {
        if let (&None, Some($thing)) = (&$slf.$thing, $other.$thing) {
            $slf.$thing = Some($thing);
        }
    };
}

macro_rules! impl_psbt_de_serialize {
    ($thing:ty) => {
        impl_psbt_serialize!($thing);
        impl_psbt_deserialize!($thing);
    };
}

macro_rules! impl_psbt_deserialize {
    ($thing:ty) => {
        impl $crate::util::psbt::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::consensus::encode::Error> {
                $crate::consensus::deserialize(&bytes[..])
            }
        }
    };
}

macro_rules! impl_psbt_serialize {
    ($thing:ty) => {
        impl $crate::util::psbt::serialize::Serialize for $thing {
            fn serialize(&self) -> $crate::prelude::Vec<u8> {
                $crate::consensus::serialize(self)
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_encoding {
    ($thing:ty) => {
        impl $crate::consensus::Encodable for $thing {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, $crate::io::Error> {
                self.consensus_encode_map(w)
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_decoding {
    ($thing:ty) => {
        impl $crate::consensus::Decodable for $thing {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, $crate::consensus::encode::Error> {
                let mut rv: Self = core::default::Default::default();

                loop {
                    match $crate::consensus::Decodable::consensus_decode(r) {
                        Ok(pair) => rv.insert_pair(pair)?,
                        Err($crate::consensus::encode::Error::Psbt($crate::util::psbt::Error::NoMorePairs)) => return Ok(rv),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_enc_dec_oding {
    ($thing:ty) => {
        impl_psbtmap_consensus_decoding!($thing);
        impl_psbtmap_consensus_encoding!($thing);
    };
}

#[rustfmt::skip]
macro_rules! impl_psbt_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::util::psbt::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err($crate::util::psbt::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::util::psbt::Error::InvalidKey($raw_key).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key.is_empty() {
            let key_val: $keyed_key_type = $crate::util::psbt::serialize::Deserialize::deserialize(&$raw_key.key)?;
            match $slf.$keyed_name.entry(key_val) {
                $crate::prelude::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = $crate::util::psbt::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                $crate::prelude::btree_map::Entry::Occupied(_) => return Err($crate::util::psbt::Error::DuplicateKey($raw_key).into()),
            }
        } else {
            return Err($crate::util::psbt::Error::InvalidKey($raw_key).into());
        }
    };
}

#[rustfmt::skip]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::util::psbt::raw::Pair {
                key: $crate::util::psbt::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: $crate::util::psbt::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::util::psbt::raw::Pair {
                key: $crate::util::psbt::raw::Key {
                    type_value: $keyed_typeval,
                    key: $crate::util::psbt::serialize::Serialize::serialize(key),
                },
                value: $crate::util::psbt::serialize::Serialize::serialize(val),
            });
        }
    };
}

// macros for serde of hashes
macro_rules! impl_psbt_hash_de_serialize {
    ($hash_type:ty) => {
        impl_psbt_hash_serialize!($hash_type);
        impl_psbt_hash_deserialize!($hash_type);
    };
}

macro_rules! impl_psbt_hash_deserialize {
    ($hash_type:ty) => {
        impl $crate::util::psbt::serialize::Deserialize for $hash_type {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::consensus::encode::Error> {
                <$hash_type>::from_slice(&bytes[..]).map_err(|e| {
                    $crate::util::psbt::Error::from(e).into()
                })
            }
        }
    };
}

macro_rules! impl_psbt_hash_serialize {
    ($hash_type:ty) => {
        impl $crate::util::psbt::serialize::Serialize for $hash_type {
            fn serialize(&self) -> $crate::prelude::Vec<u8> {
                self.into_inner().to_vec()
            }
        }
    };
}
