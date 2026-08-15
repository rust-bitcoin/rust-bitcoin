// SPDX-License-Identifier: CC0-1.0

//! Tests to ensure serde deserialization maintains type invariants.
//!
//! These tests verify that types with validation constraints properly reject
//! invalid values during deserialization, preventing invariant violations.

#![cfg(feature = "serde")]

use bitcoin_units::locktime::absolute::{Height, MedianTimePast};
use bitcoin_units::{Amount, SignedAmount};

/// Test that Height rejects values in the time range during deserialization.
///
/// Height must be in range `[0, 499_999_999]`. Values `>= 500_000_000` represent
/// timestamps and should be rejected.
#[test]
fn height_rejects_time_values_during_deserialization() {
    // Valid height values should deserialize successfully
    let valid_json = "499999999";
    let height: Height = serde_json::from_str(valid_json).expect("valid height");
    assert_eq!(height.to_u32(), 499_999_999);

    // Time values (>= 500_000_000) should fail
    let invalid_json = "500000000";
    let result: Result<Height, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "Height should reject time values");

    // Maximum u32 should also fail
    let invalid_json = "4294967295";
    let result: Result<Height, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "Height should reject u32::MAX");
}

/// Test that `MedianTimePast` rejects height values during deserialization.
///
/// `MedianTimePast` must be in range `[500_000_000, u32::MAX]`. Values `< 500_000_000`
/// represent block heights and should be rejected.
#[test]
fn median_time_past_rejects_height_values_during_deserialization() {
    // Valid time values should deserialize successfully
    let valid_json = "500000000";
    let time: MedianTimePast = serde_json::from_str(valid_json).expect("valid time");
    assert_eq!(time.to_u32(), 500_000_000);

    // Height values (< 500_000_000) should fail
    let invalid_json = "499999999";
    let result: Result<MedianTimePast, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "MedianTimePast should reject height values");

    // Zero should also fail
    let invalid_json = "0";
    let result: Result<MedianTimePast, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "MedianTimePast should reject zero");
}

/// Test that Amount rejects values exceeding `MAX_MONEY` during deserialization.
///
/// Amount must not exceed 21,000,000 BTC (2,100,000,000,000,000 satoshis).
#[test]
fn amount_rejects_values_exceeding_max_money() {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestAmount {
        #[serde(with = "bitcoin_units::amount::serde::as_sat")]
        amount: Amount,
    }

    // Valid amount should deserialize
    let valid_json = r#"{"amount":2100000000000000}"#;
    let test: TestAmount = serde_json::from_str(valid_json).expect("valid amount");
    assert_eq!(test.amount, Amount::MAX_MONEY);

    // Amount exceeding MAX_MONEY should fail
    let invalid_json = r#"{"amount":2100000000000001}"#;
    let result: Result<TestAmount, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "Amount should reject values > MAX_MONEY");

    // Maximum u64 should fail
    let invalid_json = r#"{"amount":18446744073709551615}"#;
    let result: Result<TestAmount, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "Amount should reject u64::MAX");
}

/// Test that `SignedAmount` rejects values outside valid range during deserialization.
///
/// `SignedAmount` must be in range [-21,000,000 BTC, +21,000,000 BTC].
#[test]
fn signed_amount_rejects_out_of_range_values() {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestSignedAmount {
        #[serde(with = "bitcoin_units::amount::serde::as_sat")]
        amount: SignedAmount,
    }

    // Valid positive amount
    let valid_json = r#"{"amount":2100000000000000}"#;
    let test: TestSignedAmount = serde_json::from_str(valid_json).expect("valid amount");
    assert_eq!(test.amount, SignedAmount::MAX_MONEY);

    // Valid negative amount
    let valid_json = r#"{"amount":-2100000000000000}"#;
    let test: TestSignedAmount = serde_json::from_str(valid_json).expect("valid negative amount");
    assert_eq!(test.amount, SignedAmount::MIN);

    // Positive amount exceeding MAX_MONEY should fail
    let invalid_json = r#"{"amount":2100000000000001}"#;
    let result: Result<TestSignedAmount, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "SignedAmount should reject values > MAX_MONEY");

    // Negative amount below MIN should fail
    let invalid_json = r#"{"amount":-2100000000000001}"#;
    let result: Result<TestSignedAmount, _> = serde_json::from_str(invalid_json);
    assert!(result.is_err(), "SignedAmount should reject values < MIN");
}

/// Test that Height and `MedianTimePast` maintain their mutual exclusivity invariant.
///
/// The ranges `[0, 499_999_999]` for Height and `[500_000_000, u32::MAX]` for
/// `MedianTimePast` are mutually exclusive by design to distinguish block heights
/// from timestamps in the locktime consensus rules.
#[test]
fn locktime_types_maintain_mutual_exclusivity() {
    // The boundary value 499_999_999 is valid for Height
    let json = "499999999";
    assert!(serde_json::from_str::<Height>(json).is_ok());
    assert!(serde_json::from_str::<MedianTimePast>(json).is_err());

    // The boundary value 500_000_000 is valid for MedianTimePast
    let json = "500000000";
    assert!(serde_json::from_str::<Height>(json).is_err());
    assert!(serde_json::from_str::<MedianTimePast>(json).is_ok());

    // No u32 value should be valid for both types
    for value in [0, 100_000, 499_999_999, 500_000_000, 1_000_000_000, u32::MAX] {
        let json = value.to_string();
        let height_ok = serde_json::from_str::<Height>(&json).is_ok();
        let time_ok = serde_json::from_str::<MedianTimePast>(&json).is_ok();
        assert!(
            !(height_ok && time_ok),
            "Value {} should not be valid for both Height and MedianTimePast",
            value
        );
    }
}

/// Test roundtrip serialization maintains invariants.
///
/// Ensures that serialize -> deserialize -> serialize produces identical results
/// and maintains all type invariants.
#[test]
fn roundtrip_serialization_maintains_invariants() {
    // Height roundtrip
    let height = Height::from_u32(123_456).unwrap();
    let json = serde_json::to_string(&height).unwrap();
    let deserialized: Height = serde_json::from_str(&json).unwrap();
    assert_eq!(height, deserialized);
    assert_eq!(serde_json::to_string(&deserialized).unwrap(), json);

    // MedianTimePast roundtrip
    let time = MedianTimePast::from_u32(1_234_567_890).unwrap();
    let json = serde_json::to_string(&time).unwrap();
    let deserialized: MedianTimePast = serde_json::from_str(&json).unwrap();
    assert_eq!(time, deserialized);
    assert_eq!(serde_json::to_string(&deserialized).unwrap(), json);
}
