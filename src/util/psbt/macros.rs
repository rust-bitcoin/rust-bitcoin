macro_rules! impl_psbt_de_serialize {
    ($thing:ty) => {
        impl_psbt_serialize!($thing);
        impl_psbt_deserialize!($thing);
    };
}

macro_rules! impl_psbt_deserialize {
    ($thing:ty) => {
        impl ::util::psbt::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> Result<Self, ::consensus::encode::Error> {
                ::consensus::encode::deserialize(&bytes[..])
            }
        }
    };
}

macro_rules! impl_psbt_serialize {
    ($thing:ty) => {
        impl ::util::psbt::serialize::Serialize for $thing {
            fn serialize(&self) -> Vec<u8> {
                ::consensus::encode::serialize(self)
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_encoding {
    ($thing:ty) => {
        impl<S: ::consensus::encode::Encoder> ::consensus::encode::Encodable<S> for $thing {
            fn consensus_encode(&self, s: &mut S) -> Result<(), ::consensus::encode::Error> {
                for pair in ::util::psbt::Map::get_pairs(self)? {
                    ::consensus::encode::Encodable::consensus_encode(&pair, s)?
                }

                ::consensus::encode::Encodable::consensus_encode(&0x00_u8, s)
            }
        }
    };
}
