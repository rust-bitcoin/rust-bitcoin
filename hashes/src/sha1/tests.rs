#[test]
#[cfg(feature = "alloc")]
fn test() {
    use alloc::string::ToString;

    use crate::{sha1, HashEngine};

    #[derive(Clone)]
    struct Test {
        input: &'static str,
        output: [u8; 20],
        output_str: &'static str,
    }

    #[rustfmt::skip]
    let tests = [
        // Examples from wikipedia
        Test {
            input: "",
            output: [
                0xda, 0x39, 0xa3, 0xee,
                0x5e, 0x6b, 0x4b, 0x0d,
                0x32, 0x55, 0xbf, 0xef,
                0x95, 0x60, 0x18, 0x90,
                0xaf, 0xd8, 0x07, 0x09,
            ],
            output_str: "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        Test {
            input: "The quick brown fox jumps over the lazy dog",
            output: [
                0x2f, 0xd4, 0xe1, 0xc6,
                0x7a, 0x2d, 0x28, 0xfc,
                0xed, 0x84, 0x9e, 0xe1,
                0xbb, 0x76, 0xe7, 0x39,
                0x1b, 0x93, 0xeb, 0x12,
            ],
            output_str: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        },
        Test {
            input: "The quick brown fox jumps over the lazy cog",
            output: [
                0xde, 0x9f, 0x2c, 0x7f,
                0xd2, 0x5e, 0x1b, 0x3a,
                0xfa, 0xd3, 0xe8, 0x5a,
                0x0b, 0xd1, 0x7d, 0x9b,
                0x10, 0x0d, 0xb4, 0xb3,
            ],
            output_str: "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
        },
    ];

    for test in tests {
        // Hash through high-level API, check hex encoding/decoding
        let hash = sha1::Hash::hash(test.input.as_bytes());
        assert_eq!(hash, test.output_str.parse::<sha1::Hash>().expect("parse hex"));
        assert_eq!(hash.as_byte_array(), &test.output);
        assert_eq!(hash.to_string(), test.output_str);

        // Hash through engine, checking that we can input byte by byte
        let mut engine = sha1::Hash::engine();
        for ch in test.input.as_bytes() {
            engine.input(&[*ch]);
        }
        let manual_hash = sha1::Hash::from_engine(engine);
        assert_eq!(hash, manual_hash);
        assert_eq!(hash.to_byte_array(), test.output);
    }
}

#[test]
#[cfg(feature = "serde")]
fn sha1_serde() {
    use serde_test::{assert_tokens, Configure, Token};

    use crate::sha1;

    #[rustfmt::skip]
    static HASH_BYTES: [u8; 20] = [
        0x13, 0x20, 0x72, 0xdf,
        0x69, 0x09, 0x33, 0x83,
        0x5e, 0xb8, 0xb6, 0xad,
        0x0b, 0x77, 0xe7, 0xb6,
        0xf1, 0x4a, 0xca, 0xd7,
    ];

    let hash = sha1::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
    assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
    assert_tokens(&hash.readable(), &[Token::Str("132072df690933835eb8b6ad0b77e7b6f14acad7")]);
}
