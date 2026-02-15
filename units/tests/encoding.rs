// SPDX-License-Identifier: CC0-1.0

//! Test the consensus encoding implementations for types in `units`.

#![cfg(feature = "alloc")]
#![cfg(feature = "encoding")]

use bitcoin_units::absolute::{LockTime, LockTimeDecoder};
use bitcoin_units::amount::AmountDecoder;
use bitcoin_units::block::BlockHeightDecoder;
use bitcoin_units::sequence::SequenceDecoder;
use bitcoin_units::time::BlockTimeDecoder;
use bitcoin_units::{Amount, BlockHeight, BlockTime, Sequence};
use encoding::{encode_to_vec, Decodable as _, Decoder as _};

/// Tests round-trip encoding/decoding for a list of values.
///
/// For each value: encodes it, decodes it back using the provided decoder type,
/// and verifies the decoded value matches the original.
macro_rules! test_round_trip {
    ($fn_name:ident, $decoder:ty, $read_limit:expr, $($value:expr),+ $(,)?) => {
        #[test]
        fn $fn_name() {
            for value in [$($value),+] {
                let encoded = encode_to_vec(&value);

                let mut decoder = <$decoder>::default();
                assert_eq!(decoder.read_limit(), $read_limit);

                decoder.push_bytes(&mut encoded.as_slice()).unwrap();
                assert_eq!(decoder.read_limit(), 0);

                let decoded = decoder.end().unwrap();
                assert_eq!(decoded, value);
            }
        }
    };
}

/// Tests that `Type::decoder()` and `TypeDecoder::default()` produce equivalent decoders.
macro_rules! test_decoder_default {
    ($fn_name:ident, $type:ty, $decoder:ty, $read_limit:expr) => {
        #[test]
        fn $fn_name() {
            let decodable_decoder = <$type>::decoder();
            let decoder_default = <$decoder>::default();
            assert_eq!(decodable_decoder.read_limit(), decoder_default.read_limit());
            assert_eq!(decodable_decoder.read_limit(), $read_limit);
        }
    };
}

/// Tests decoding from hardcoded byte arrays.
///
/// For each (bytes, `expected_value`) pair: creates a new decoder, verifies the initial
/// `read_limit`, pushes all bytes, verifies completion, and checks the decoded value.
macro_rules! test_hardcoded_decoding {
    ($fn_name:ident, $decoder:ty, $read_limit:expr$(, ($bytes:expr, $expected:expr))+ $(,)?) => {
        #[test]
        fn $fn_name() {
            $(
                let bytes = $bytes;
                let mut decoder = <$decoder>::new();
                assert_eq!(decoder.read_limit(), $read_limit);

                let needs_more = decoder.push_bytes(&mut bytes.as_slice()).unwrap();
                assert!(!needs_more);
                assert_eq!(decoder.read_limit(), 0);

                let decoded = decoder.end().unwrap();
                assert_eq!(decoded, $expected);
            )+
        }
    };
}

/// Tests decoding from a hardcoded array, feeding bytes one at a time.
macro_rules! test_incremental_decoding {
    ($fn_name:ident, $decoder:ty, $read_limit:expr$(, ($bytes:expr, $expected:expr))+ $(,)?) => {
        #[test]
        fn $fn_name() {
            $(
                let bytes = $bytes;

                let mut decoder = <$decoder>::new();
                assert_eq!(decoder.read_limit(), $read_limit);

                // Feed bytes one at a time
                for (i, byte) in bytes.iter().enumerate() {
                    let slice = &[*byte];
                    let needs_more = decoder.push_bytes(&mut slice.as_slice()).unwrap();
                    assert_eq!(decoder.read_limit(), $read_limit - 1 - i);
                    assert_eq!(needs_more, i < $read_limit - 1); // true until the last loop
                }

                let decoded = decoder.end().unwrap();
                assert_eq!(decoded, $expected);
            )+
        }
    };
}

// Amount encodes as 8-byte little-endian u64 (satoshis).
// 1 BTC = 100_000_000 satoshis = 0x05F5E100
// As little-endian: [0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]
#[test]
fn amount_hardcoded_encoding() {
    let amount = Amount::from_sat(100_000_000).unwrap(); // 1 BTC
    let encoded = encode_to_vec(&amount);
    assert_eq!(encoded, [0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]);
}

test_hardcoded_decoding!(
    amount_hardcoded_decoding,
    AmountDecoder,
    8,
    ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], Amount::ZERO),
    ([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], Amount::ONE_SAT),
    ([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00], Amount::ONE_BTC), // 100_000_000 sats
    ([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00], Amount::from_sat(100_000_000).unwrap()), // 1 BTC
    (
        [0x00, 0x40, 0x07, 0x5a, 0xf0, 0x75, 0x07, 0x00],
        Amount::from_sat(21_000_000 * 100_000_000).unwrap()
    ), // 21M BTC
);

test_decoder_default!(amount_decoder_default, Amount, AmountDecoder, 8);

test_round_trip!(
    amount_round_trip,
    AmountDecoder,
    8,
    Amount::ZERO,
    Amount::ONE_SAT,
    Amount::ONE_BTC,
    Amount::MAX,
    Amount::from_sat(21_000_000 * 100_000_000).unwrap(), // 21 million BTC
);

test_incremental_decoding!(
    amount_incremental_decoding,
    AmountDecoder,
    8,
    ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], Amount::ZERO),
    ([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], Amount::ONE_SAT),
    ([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00], Amount::ONE_BTC), // 100_000_000 sats
    ([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00], Amount::from_sat(100_000_000).unwrap()), // 1 BTC
    (
        [0x00, 0x40, 0x07, 0x5a, 0xf0, 0x75, 0x07, 0x00],
        Amount::from_sat(21_000_000 * 100_000_000).unwrap()
    ), // 21M BTC
);

// BlockHeight encodes as 4-byte little-endian u32.
// Height 840000 = 0x000CD140
// As little-endian: [0x40, 0xD1, 0x0C, 0x00]
#[test]
fn block_height_hardcoded_encoding() {
    let height = BlockHeight::from_u32(840_000);
    let encoded = encode_to_vec(&height);
    assert_eq!(encoded, [0x40, 0xd1, 0x0c, 0x00]);
}

test_hardcoded_decoding!(
    block_height_hardcoded_decoding,
    BlockHeightDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], BlockHeight::from_u32(0)),
    ([0x20, 0xa1, 0x07, 0x00], BlockHeight::from_u32(500_000)),
    ([0x40, 0xd1, 0x0c, 0x00], BlockHeight::from_u32(840_000)),
    ([0xff, 0xff, 0xff, 0xff], BlockHeight::from_u32(u32::MAX)),
);

test_decoder_default!(block_height_decoder_default, BlockHeight, BlockHeightDecoder, 4);

test_round_trip!(
    block_height_round_trip,
    BlockHeightDecoder,
    4,
    BlockHeight::MIN,
    BlockHeight::MAX,
    BlockHeight::from_u32(0),
    BlockHeight::from_u32(500_000),
    BlockHeight::from_u32(840_000),
);

test_incremental_decoding!(
    block_height_incremental_decoding,
    BlockHeightDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], BlockHeight::from_u32(0)),
    ([0x20, 0xa1, 0x07, 0x00], BlockHeight::from_u32(500_000)),
    ([0x40, 0xd1, 0x0c, 0x00], BlockHeight::from_u32(840_000)),
    ([0xff, 0xff, 0xff, 0xff], BlockHeight::from_u32(u32::MAX)),
);

// BlockTime encodes as 4-byte little-endian u32 (Unix timestamp).
// 1713657600 = 0x66245700 (2024-04-21 00:00:00 UTC)
// As little-endian: [0x00, 0x57, 0x24, 0x66]
#[test]
fn block_time_hardcoded_encoding() {
    let time = BlockTime::from_u32(1_713_657_600);
    let encoded = encode_to_vec(&time);
    assert_eq!(encoded, [0x00, 0x57, 0x24, 0x66]);
}

test_hardcoded_decoding!(
    block_time_hardcoded_decoding,
    BlockTimeDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], BlockTime::from_u32(0)),
    ([0x29, 0xab, 0x5f, 0x49], BlockTime::from_u32(1_231_006_505)), // Bitcoin genesis block
    ([0x00, 0x57, 0x24, 0x66], BlockTime::from_u32(1_713_657_600)), // 2024-04-21
    ([0xff, 0xff, 0xff, 0xff], BlockTime::from_u32(u32::MAX)),
);

test_decoder_default!(block_time_decoder_default, BlockTime, BlockTimeDecoder, 4);

test_round_trip!(
    block_time_round_trip,
    BlockTimeDecoder,
    4,
    BlockTime::from_u32(0),
    BlockTime::from_u32(1_231_006_505), // Bitcoin genesis block timestamp
    BlockTime::from_u32(1_713_657_600), // 2024-04-21
    BlockTime::from_u32(u32::MAX),
);

test_incremental_decoding!(
    block_time_incremental_decoding,
    BlockTimeDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], BlockTime::from_u32(0)),
    ([0x29, 0xab, 0x5f, 0x49], BlockTime::from_u32(1_231_006_505)), // Bitcoin genesis block
    ([0x00, 0x57, 0x24, 0x66], BlockTime::from_u32(1_713_657_600)), // 2024-04-21
    ([0xff, 0xff, 0xff, 0xff], BlockTime::from_u32(u32::MAX)),
);

// Sequence encodes as 4-byte little-endian u32.
// MAX = 0xFFFFFFFF
// ZERO = 0x00000000
#[test]
fn sequence_hardcoded_encoding() {
    let seq = Sequence::MAX;
    let encoded = encode_to_vec(&seq);
    assert_eq!(encoded, [0xff, 0xff, 0xff, 0xff]);

    let seq_zero = Sequence::ZERO;
    let encoded_zero = encode_to_vec(&seq_zero);
    assert_eq!(encoded_zero, [0x00, 0x00, 0x00, 0x00]);
}

test_hardcoded_decoding!(
    sequence_hardcoded_decoding,
    SequenceDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], Sequence::ZERO),
    ([0xfd, 0xff, 0xff, 0xff], Sequence::ENABLE_LOCKTIME_AND_RBF), // 0xfffffffd
    ([0xfe, 0xff, 0xff, 0xff], Sequence::ENABLE_LOCKTIME_NO_RBF),  // 0xfffffffe
    ([0xff, 0xff, 0xff, 0xff], Sequence::MAX),
);

test_decoder_default!(sequence_decoder_default, Sequence, SequenceDecoder, 4);

test_round_trip!(
    sequence_round_trip,
    SequenceDecoder,
    4,
    Sequence::MAX,
    Sequence::ZERO,
    Sequence::ENABLE_LOCKTIME_AND_RBF,
    Sequence::ENABLE_LOCKTIME_NO_RBF,
);

test_incremental_decoding!(
    sequence_incremental_decoding,
    SequenceDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], Sequence::ZERO),
    ([0xfd, 0xff, 0xff, 0xff], Sequence::ENABLE_LOCKTIME_AND_RBF), // 0xfffffffd
    ([0xfe, 0xff, 0xff, 0xff], Sequence::ENABLE_LOCKTIME_NO_RBF),  // 0xfffffffe
    ([0xff, 0xff, 0xff, 0xff], Sequence::MAX),
);

// LockTime (absolute) encodes as 4-byte little-endian u32.
// Height 500000 = 0x0007A120
// As little-endian: [0x20, 0xa1, 0x07, 0x00]
#[test]
fn locktime_height_hardcoded_encoding() {
    let locktime = LockTime::from_height(500_000).unwrap();
    let encoded = encode_to_vec(&locktime);
    assert_eq!(encoded, [0x20, 0xa1, 0x07, 0x00]);
}

test_hardcoded_decoding!(
    locktime_height_hardcoded_decoding,
    LockTimeDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], LockTime::ZERO),
    ([0x20, 0xa1, 0x07, 0x00], LockTime::from_height(500_000).unwrap()),
    ([0xff, 0x64, 0xcd, 0x1d], LockTime::from_height(499_999_999).unwrap()),
);

test_incremental_decoding!(
    locktime_height_incremental_decoding,
    LockTimeDecoder,
    4,
    ([0x00, 0x00, 0x00, 0x00], LockTime::ZERO),
    ([0x20, 0xa1, 0x07, 0x00], LockTime::from_height(500_000).unwrap()),
    ([0xff, 0x64, 0xcd, 0x1d], LockTime::from_height(499_999_999).unwrap()),
);

// LockTime (time-based): values >= 500_000_000 are interpreted as Unix timestamps.
// 1_700_000_000 = 0x6553F100
// As little-endian: [0x00, 0xf1, 0x53, 0x65]
#[test]
fn locktime_time_hardcoded_encoding() {
    let locktime = LockTime::from_mtp(1_700_000_000).unwrap();
    let encoded = encode_to_vec(&locktime);
    assert_eq!(encoded, [0x00, 0xf1, 0x53, 0x65]);
}

test_hardcoded_decoding!(
    locktime_time_hardcoded_decoding,
    LockTimeDecoder,
    4,
    ([0x00, 0x65, 0xcd, 0x1d], LockTime::from_mtp(500_000_000).unwrap()),
    ([0x00, 0xf1, 0x53, 0x65], LockTime::from_mtp(1_700_000_000).unwrap()),
    ([0xff, 0xff, 0xff, 0xff], LockTime::from_mtp(u32::MAX).unwrap()),
);

test_incremental_decoding!(
    locktime_time_incremental_decoding,
    LockTimeDecoder,
    4,
    ([0x00, 0x65, 0xcd, 0x1d], LockTime::from_mtp(500_000_000).unwrap()),
    ([0x00, 0xf1, 0x53, 0x65], LockTime::from_mtp(1_700_000_000).unwrap()),
    ([0xff, 0xff, 0xff, 0xff], LockTime::from_mtp(u32::MAX).unwrap()),
);

// Tests for both types of LockTime
test_decoder_default!(locktime_decoder_default, LockTime, LockTimeDecoder, 4);

test_round_trip!(
    locktime_round_trip,
    LockTimeDecoder,
    4,
    LockTime::ZERO,
    LockTime::from_height(0).unwrap(),
    LockTime::from_height(499_999_999).unwrap(),
    LockTime::from_mtp(500_000_000).unwrap(),
    LockTime::from_mtp(u32::MAX).unwrap(),
);
