# Serde Deserialization Invariants Audit

**Date**: 2026-08-15  
**Issue**: Review all data structures to ensure that they maintain invariants while deserializing from serde

## Executive Summary

✅ **All critical data structures in rust-bitcoin properly maintain their invariants during serde deserialization.**

The codebase consistently uses defensive programming patterns that prevent invariant violations:
- Custom `Deserialize` implementations that call validation constructors
- Encapsulation with private fields and validated constructors
- Custom serde modules instead of derive macros for sensitive types
- Some types don't support serde at all

## Audited Types

### 1. Locktime Types (units/src/locktime/)

#### `Height`
- **Invariant**: Must be in range `[0, 499_999_999]` (block heights)
- **Protection**: Custom `Deserialize` calls `Height::from_u32()` which validates range
- **Status**: ✅ SAFE

```rust
impl<'de> Deserialize<'de> for Height {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
    {
        Self::from_u32(u32::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
```

#### `MedianTimePast`
- **Invariant**: Must be in range `[500_000_000, u32::MAX]` (timestamps)
- **Protection**: Custom `Deserialize` calls `MedianTimePast::from_u32()` which validates range
- **Status**: ✅ SAFE

```rust
impl<'de> Deserialize<'de> for MedianTimePast {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where D: Deserializer<'de>
    {
        Self::from_u32(u32::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
```

#### `LockTime`
- **Invariant**: Enum with two variants, constructed from consensus u32
- **Protection**: Custom `Deserialize` calls `LockTime::from_consensus()` which properly constructs the enum
- **Status**: ✅ SAFE

### 2. Amount Types (units/src/amount/)

#### `Amount`
- **Invariant**: Must not exceed `MAX_MONEY` (21,000,000 BTC = 2,100,000,000,000,000 satoshis)
- **Protection**: 
  - Encapsulation pattern with private inner field `Amount(u64)`
  - No `derive(Deserialize)` - all deserialization through custom serde modules
  - Serde modules validate via `Amount::from_sat()` which checks `<= MAX_MONEY`
- **Status**: ✅ SAFE

#### `SignedAmount`
- **Invariant**: Must be in range `[MIN, MAX_MONEY]` (±21M BTC)
- **Protection**: 
  - Encapsulation pattern with private inner field `SignedAmount(i64)`
  - No `derive(Deserialize)`
  - Custom serde modules validate range
- **Status**: ✅ SAFE

### 3. Fee Rate (units/src/fee_rate/)

#### `FeeRate`
- **Invariant**: Represents satoshis per million virtual bytes (internal representation)
- **Protection**:
  - Encapsulation pattern with private inner field `FeeRate(u64)`
  - No `derive(Deserialize)` on the struct itself
  - Custom serde modules for different denominations
- **Status**: ✅ SAFE

### 4. Address Types (addresses/src/)

#### `Address<V>`
- **Invariant**: Must be a valid Bitcoin address with proper checksums and format
- **Protection**: Custom `Deserialize` that:
  1. Parses string via `FromStr` trait
  2. `FromStr` implementation validates bech32/base58 checksums
  3. Validates address format and network indicators
- **Status**: ✅ SAFE

```rust
impl<'de, U: NetworkValidationUnchecked> serde::Deserialize<'de> for Address<U> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::de::Deserializer<'de>
    {
        // Parses via FromStr which includes full validation
        let address = v.parse::<Address<NetworkUnchecked>>().map_err(E::custom)?;
        Ok(Address::from_inner(address.to_inner()))
    }
}
```

#### `WitnessProgram`
- **Invariant**: 
  - Length must be between 2 and 40 bytes
  - v0 witness programs must be exactly 20 or 32 bytes
- **Protection**: **No serde support** - type cannot be deserialized directly
- **Status**: ✅ SAFE (by design - no deserialization)

### 5. Cryptographic Keys (crypto/src/key.rs)

#### `PrivateKey`
- **Invariant**: Must be a valid secp256k1 secret key (not all-zeros, not exceeding curve order)
- **Protection**: Custom construction via `from_secret_bytes()` which validates
- **Status**: ✅ SAFE

#### `LegacyPublicKey`
- **Invariant**: Must be valid secp256k1 public key, maintains compressed/uncompressed state
- **Protection**: Custom deserialization that validates key format and structure
- **Status**: ✅ SAFE

#### `XOnlyPublicKey`
- **Invariant**: Valid 32-byte x-only public key with parity
- **Protection**: Validation through cryptographic library checks
- **Status**: ✅ SAFE

## Defensive Patterns Observed

The rust-bitcoin codebase uses several defensive patterns consistently:

### 1. Encapsulation with Private Fields
```rust
mod encapsulate {
    pub struct Amount(u64);  // Private field
    
    impl Amount {
        pub const fn from_sat(satoshi: u64) -> Result<Self, OutOfRangeError> {
            if satoshi > Self::MAX_MONEY.to_sat() {
                Err(OutOfRangeError { ... })
            } else {
                Ok(Self(satoshi))
            }
        }
    }
}
```

### 2. Custom Deserialize Implementations
```rust
impl<'de> Deserialize<'de> for Height {
    fn deserialize<D>(d: D) -> Result<Self, D::Error> {
        Self::from_u32(u32::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
```

### 3. Custom Serde Modules
```rust
#[serde(with = "bitcoin_units::amount::serde::as_sat")]
amount: Amount,
```

### 4. No Serde Support
Some types with complex invariants simply don't support serde deserialization.

## Testing Recommendations

While the current implementations are secure, the following tests should be added to ensure ongoing protection:

### Test Invalid Deserialization Cases

1. **Height deserialization**:
   - Test that deserializing `500_000_000` (time, not height) fails
   - Test that deserializing `u32::MAX` fails

2. **MedianTimePast deserialization**:
   - Test that deserializing `499_999_999` (height, not time) fails
   - Test that deserializing `0` fails

3. **Amount deserialization**:
   - Test that deserializing `MAX_MONEY + 1` fails
   - Test various serde formats (as_sat, as_btc)

4. **Address deserialization**:
   - Test that invalid checksums are rejected
   - Test that malformed addresses fail

### Example Test Template

```rust
#[cfg(test)]
mod serde_invariant_tests {
    use super::*;
    
    #[test]
    #[should_panic]
    fn height_rejects_time_values() {
        let json = "500000000"; // This is a time, not a height
        let _: Height = serde_json::from_str(json).unwrap();
    }
    
    #[test]
    fn median_time_past_rejects_height_values() {
        let json = "499999999"; // This is a height, not a time
        let result: Result<MedianTimePast, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
```

## Conclusion

**No fixes are required.** The rust-bitcoin codebase already properly maintains invariants during serde deserialization through:

1. Consistent use of validation in constructors
2. Custom `Deserialize` implementations that call these constructors
3. Encapsulation patterns that prevent bypassing validation
4. Strategic choice to not support serde for some complex types

The project demonstrates excellent defensive programming practices in this area.

## Recommendations

1. **Add explicit tests** for invalid deserialization cases (see Testing Recommendations above)
2. **Document the pattern** in CONTRIBUTING.md for new contributors
3. **Consider adding a clippy lint** or custom tool to detect `derive(Deserialize)` on types with validated constructors
4. **Maintain vigilance** when adding new types with invariants

---

**Audited by**: Claude Sonnet 4.5 (AI-assisted analysis)  
**Assisted-by**: Claude Sonnet 4.5 v20250514
