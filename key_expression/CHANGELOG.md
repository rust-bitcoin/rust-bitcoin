# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-09

- Remove uses of `Index` on `secp256k1::SecretKey` [#6871](https://github.com/rust-bitcoin/rust-bitcoin/pull/6871)
- Preserve master-key invariants in `Xpub` `Arbitrary` [#6955](https://github.com/rust-bitcoin/rust-bitcoin/pull/6955)
- Add `Xpriv::from_byte_array` and `Xpub::from_byte_array` [#7083](https://github.com/rust-bitcoin/rust-bitcoin/pull/7083)
- Refactor xpub and xpriv derive functions [#6500](https://github.com/rust-bitcoin/rust-bitcoin/pull/6500)
- Seed length validation follow-up [#6271](https://github.com/rust-bitcoin/rust-bitcoin/pull/6271)
- Split up errors [#6396](https://github.com/rust-bitcoin/rust-bitcoin/pull/6396)
- Make `Xpriv` debug formatting redact the private-key field consistently with and without `std`.
- Add checked `XprivParts`/`XpubParts` construction, xkey metadata getters, and a `secp256k1` crate re-export.
- BREAKING: Make `Xpriv`/`Xpub` fields private; use metadata getters, checked `from_parts` construction,
  and `to_parts` for raw-key access.

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
