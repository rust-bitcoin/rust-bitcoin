# Changelog

## [Unreleased]

## [0.3.0] - 2026-07-22

- Remove `PrivateKeyExt` and make `PrivateKey::as_inner` private [#6345](https://github.com/rust-bitcoin/rust-bitcoin/pull/)
- Remove `XOnlyPublicKey::as_inner` and make `to_inner` private for public keys [#5619](https://github.com/rust-bitcoin/rust-bitcoin/pull/5619)
- Remove Verification re-exports [#6319](https://github.com/rust-bitcoin/rust-bitcoin/pull/6319)
- Improve sighash errors [#6318](https://github.com/rust-bitcoin/rust-bitcoin/pull/6318)
- Add `XOnlyPublicKey::verify` [#6261](https://github.com/rust-bitcoin/rust-bitcoin/pull/6261)
- Extend ECDSA `Signature` [#6260](https://github.com/rust-bitcoin/rust-bitcoin/pull/6260)
- Split `key::encapsulate` and rename `LegacyPublicKey::to_bytes` [#6238](https://github.com/rust-bitcoin/rust-bitcoin/pull/6238)
- Introduce new errors to remove `secp256k1::Error` [#6183](https://github.com/rust-bitcoin/rust-bitcoin/pull/6183)
- Remove alloc feature gate from taproot module [#6155](https://github.com/rust-bitcoin/rust-bitcoin/pull/6155)
- Add `with_compressedness` to `LegacyPublicKey` [#6119](https://github.com/rust-bitcoin/rust-bitcoin/pull/6119)
- Clean up key module [#6118](https://github.com/rust-bitcoin/rust-bitcoin/pull/6118)
- Remove `with_serialized` from `LegacyPublicKey` [#6116](https://github.com/rust-bitcoin/rust-bitcoin/pull/6116)
- Move `taproot` module to `crypto` [#6097](https://github.com/rust-bitcoin/rust-bitcoin/pull/6097)
- Gate all usage of `hex-conservative` behind `hex` feature [#6043](https://github.com/rust-bitcoin/rust-bitcoin/pull/6043)

## [0.2.0] - 2026-04-27

- Re-export types and extern crates [#5858](https://github.com/rust-bitcoin/rust-bitcoin/pull/5858)
- Remove error conversion `From` impls [#6041](https://github.com/rust-bitcoin/rust-bitcoin/pull/6041)
- Remove `bitcoin-io` dependency [#6049](https://github.com/rust-bitcoin/rust-bitcoin/pull/6049)

## 0.1.0 - Initial migration

- Migrate all code from `rust-bitcoin::crypto::ecdsa` to this crate.
- Migrate all key types from `rust-bitcoin::crypto::key` to this crate. The `TapTweak` trait
  remains only in `rust-bitcoin`.
- Migrate sighash types and associated errors from `rust-bitcoin::crypto::sighash` to this crate.

## 0.0.0 - Initial dummy release

- Empty crate to reserve the name on crates.io

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-crypto-0.3.0...HEAD
[0.3.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-crypto-0.2.0...bitcoin-crypto-0.3.0
[0.2.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-crypto-0.1.0...bitcoin-crypto-0.2.0
