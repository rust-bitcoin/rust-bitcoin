// SPDX-License-Identifier: CC0-1.0

#[allow(unused_macros)]
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

macro_rules! impl_psbt_serialize {
    ($thing:ty) => {
        impl $crate::psbt::serialize::Serialize for $thing {
            fn serialize(&self) -> $crate::prelude::Vec<u8> { $crate::consensus::serialize(self) }
        }
    };
}

macro_rules! impl_psbt_deserialize {
    ($thing:ty) => {
        impl $crate::psbt::serialize::Deserialize for $thing {
            fn deserialize(
                bytes: &[u8],
            ) -> core::result::Result<Self, $crate::psbt::serialize::Error> {
                $crate::consensus::deserialize(&bytes[..])
                    .map_err(|e| $crate::psbt::serialize::Error::from(e))
            }
        }
    };
}

macro_rules! impl_psbtmap_serialize {
    ($thing:ty) => {
        impl $crate::psbt::serialize::Serialize for $thing {
            fn serialize(&self) -> Vec<u8> { self.serialize_map() }
        }
    };
}

#[rustfmt::skip]
macro_rules! impl_psbt_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key_data.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::psbt::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err(InsertPairError::DuplicateKey($raw_key).into());
            }
        } else {
            return Err(InsertPairError::InvalidKeyDataNotEmpty($raw_key).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key_data.is_empty() {
            let key_val: $keyed_key_type = $crate::psbt::serialize::Deserialize::deserialize(&$raw_key.key_data)?;
            match $slf.$keyed_name.entry(key_val) {
                $crate::prelude::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = $crate::psbt::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                $crate::prelude::btree_map::Entry::Occupied(_) => return Err(InsertPairError::DuplicateKey($raw_key).into()),
            }
        } else {
            return Err(InsertPairError::InvalidKeyDataEmpty($raw_key).into());
        }
    };
}

#[rustfmt::skip]
macro_rules! psbt_insert_hash_pair {
    (&mut $slf:ident.$map:ident <= $raw_key:ident|$raw_value:ident|$hash:path|$hash_type_error:path) => {
        if $raw_key.key_data.is_empty() {
            return Err(InsertPairError::InvalidKeyDataEmpty($raw_key));
        }
        let key_val: $hash = Deserialize::deserialize(&$raw_key.key_data)?;
        match $slf.$map.entry(key_val) {
            btree_map::Entry::Vacant(empty_key) => {
                let val: Vec<u8> = Deserialize::deserialize(&$raw_value)?;
                if <$hash as hashes::GeneralHash>::hash(&val) != key_val {
                    return Err(InsertPairError::InvalidPreimageHashPair {
                        preimage: val.into_boxed_slice(),
                        hash: Box::from(key_val.borrow()),
                        hash_type: $hash_type_error,
                    });
                }
                empty_key.insert(val);
            }
            $crate::prelude::btree_map::Entry::Occupied(_) => return Err(InsertPairError::DuplicateKey($raw_key).into()),
        }
    }
}

#[rustfmt::skip]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::psbt::raw::Pair {
                key: $crate::psbt::raw::Key {
                    type_value: $unkeyed_typeval,
                    key_data: vec![],
                },
                value: $crate::psbt::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::psbt::raw::Pair {
                key: $crate::psbt::raw::Key {
                    type_value: $keyed_typeval,
                    key_data: $crate::psbt::serialize::Serialize::serialize(key),
                },
                value: $crate::psbt::serialize::Serialize::serialize(val),
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
        impl $crate::psbt::serialize::Deserialize for $hash_type {
            fn deserialize(
                bytes: &[u8],
            ) -> core::result::Result<Self, $crate::psbt::serialize::Error> {
                <$hash_type>::from_slice(&bytes[..])
                    .map_err(|e| $crate::psbt::serialize::Error::from(e))
            }
        }
    };
}

macro_rules! impl_psbt_hash_serialize {
    ($hash_type:ty) => {
        impl $crate::psbt::serialize::Serialize for $hash_type {
            fn serialize(&self) -> $crate::prelude::Vec<u8> { self.as_byte_array().to_vec() }
        }
    };
}
