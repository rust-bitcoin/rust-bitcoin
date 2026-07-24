# Changelog

## [Unreleased]

## [0.2.0] - 2026-07-17

- Move `bip32` module to `key-expression` crate [#6009](https://github.com/rust-bitcoin/rust-bitcoin/pull/6009)
- Make child number a newtype `ChildNumber(u32)` [#6192](https://github.com/rust-bitcoin/rust-bitcoin/pull/6192)
- Split relative and absolute bip32 derivation paths [#6232](https://github.com/rust-bitcoin/rust-bitcoin/pull/6232)
- validate master key seed length [#6212](https://github.com/rust-bitcoin/rust-bitcoin/pull/6212)
- Seed length validation follow-up [#6271](https://github.com/rust-bitcoin/rust-bitcoin/pull/6271)
- Split up errors [#6396](https://github.com/rust-bitcoin/rust-bitcoin/pull/6396)

## [0.1.0] - 2026-05-28

- Split relative and absolute `bip32` derivation paths [#6232](https://github.com/rust-bitcoin/rust-bitcoin/pull/6232)
- Validate master key seed length [#6212](https://github.com/rust-bitcoin/rust-bitcoin/pull/6212)
- Make child number a newtype `ChildNumber(u32)` [#6192](https://github.com/rust-bitcoin/rust-bitcoin/pull/6192)
- Move `bip32` module to key-expression crate [#6009](https://github.com/rust-bitcoin/rust-bitcoin/pull/6009)

## 0.0.0 - Initial dummy release

- Empty crate to reserve the name on crates.io

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-key-expression-0.2.0...HEAD
[0.2.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-key-expression-0.1.0...bitcoin-key-expression-0.2.0
[0.1.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-key-expression-0.0.0...bitcoin-key-expression-0.1.0
