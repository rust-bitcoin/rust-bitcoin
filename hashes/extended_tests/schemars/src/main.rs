fn main() {}
#[cfg(test)]
mod tests {
    use bitcoin_hashes::*;

    #[test]
    fn hash160() {
        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf, 0x69, 0x09, 0x33, 0x83, 0x5e, 0xb8, 0xb6, 0xad, 0x0b, 0x77,
            0xe7, 0xb6, 0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = hash160::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(hash160::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn hmac_sha512() {
        static HASH_BYTES: [u8; 64] = [
            0x8b, 0x41, 0xe1, 0xb7, 0x8a, 0xd1, 0x15, 0x21, 0x11, 0x3c, 0x52, 0xff, 0x18, 0x2a,
            0x1b, 0x8e, 0x0a, 0x19, 0x57, 0x54, 0xaa, 0x52, 0x7f, 0xcd, 0x00, 0xa4, 0x11, 0x62,
            0x0b, 0x46, 0xf2, 0x0f, 0xff, 0xfb, 0x80, 0x88, 0xcc, 0xf8, 0x54, 0x97, 0x12, 0x1a,
            0xd4, 0x49, 0x9e, 0x08, 0x45, 0xb8, 0x76, 0xf6, 0xdd, 0x66, 0x40, 0x08, 0x8a, 0x2f,
            0x0b, 0x2d, 0x8a, 0x60, 0x0b, 0xdf, 0x4c, 0x0c,
        ];

        let hash = Hmac::<sha512::Hash>::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(Hmac::<sha512::Hash>);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn ripemd160() {
        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf, 0x69, 0x09, 0x33, 0x83, 0x5e, 0xb8, 0xb6, 0xad, 0x0b, 0x77,
            0xe7, 0xb6, 0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = ripemd160::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(ripemd160::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn sha1() {
        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf, 0x69, 0x09, 0x33, 0x83, 0x5e, 0xb8, 0xb6, 0xad, 0x0b, 0x77,
            0xe7, 0xb6, 0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = sha1::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(sha1::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn sha256d() {
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6,
            0x3d, 0x97, 0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
            0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256d::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(sha256d::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn sha256() {
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6,
            0x3d, 0x97, 0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
            0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(sha256::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn test_hash() {
        const TEST_MIDSTATE: [u8; 32] = [
            156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243,
            147, 108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
        ];

        #[derive(
            Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash, schemars::JsonSchema,
        )]
        pub struct TestHashTag;

        impl sha256t::Tag for TestHashTag {
            fn engine() -> sha256::HashEngine {
                // The TapRoot TapLeaf midstate.
                let midstate = sha256::Midstate::from_byte_array(TEST_MIDSTATE);
                sha256::HashEngine::from_midstate(midstate, 64)
            }
        }

        /// A hash tagged with `$name`.
        pub type TestHash = sha256t::Hash<TestHashTag>;

        sha256t_hash_newtype!(
            NewTypeHash,
            NewTypeTag,
            TEST_MIDSTATE,
            64,
            doc = "test hash",
            backward
        );
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7, 0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6,
            0x3d, 0x97, 0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
            0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = TestHash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(TestHash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn sha512() {
        static HASH_BYTES: [u8; 64] = [
            0x8b, 0x41, 0xe1, 0xb7, 0x8a, 0xd1, 0x15, 0x21, 0x11, 0x3c, 0x52, 0xff, 0x18, 0x2a,
            0x1b, 0x8e, 0x0a, 0x19, 0x57, 0x54, 0xaa, 0x52, 0x7f, 0xcd, 0x00, 0xa4, 0x11, 0x62,
            0x0b, 0x46, 0xf2, 0x0f, 0xff, 0xfb, 0x80, 0x88, 0xcc, 0xf8, 0x54, 0x97, 0x12, 0x1a,
            0xd4, 0x49, 0x9e, 0x08, 0x45, 0xb8, 0x76, 0xf6, 0xdd, 0x66, 0x40, 0x08, 0x8a, 0x2f,
            0x0b, 0x2d, 0x8a, 0x60, 0x0b, 0xdf, 0x4c, 0x0c,
        ];

        let hash = sha512::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(sha512::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }

    #[test]
    fn siphash24() {
        static HASH_BYTES: [u8; 8] = [0x8b, 0x41, 0xe1, 0xb7, 0x8a, 0xd1, 0x15, 0x21];

        let hash = siphash24::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        let js = serde_json::from_str(&serde_json::to_string(&hash).unwrap()).unwrap();
        let s = schemars::schema_for!(siphash24::Hash);
        let schema = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(jsonschema_valid::Config::from_schema(&schema, None)
            .unwrap()
            .validate(&js)
            .is_ok());
    }
}
