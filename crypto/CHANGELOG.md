# Changelog

## [Unreleased]

## [0.2.0] - 2026-04-27

- Re-export types and extern crates [#5858](https://github.com/rust-bitcoin/rust-bitcoin/pull/5858)
- Remove error conversion `From` impls [#6041](https://github.com/rust-bitcoin/rust-bitcoin/pull/6041)
- Remove `bitcoin-io` dependency [#6049](https://github.com/rust-bitcoin/rust-bitcoin/pull/6049)

## [0.1.0] - Initial migration

- Migrate all code from `rust-bitcoin::crypto::ecdsa` to this crate.
- Migrate all key types from `rust-bitcoin::crypto::key` to this crate. The `TapTweak` trait
  remains only in `rust-bitcoin`.
- Migrate sighash types and associated errors from `rust-bitcoin::crypto::sighash` to this crate.

## 0.0.0 - Initial dummy release

- Empty crate to reserve the name on crates.io

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-crypto-0.2.0...HEAD
[0.2.0]: https://github.com/rust-bitcoin/rust-bitcoin/releases/tag/bitcoin-crypto-0.2.0
[0.1.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-crypto-0.1.0...bitcoin-crypto-0.2.0