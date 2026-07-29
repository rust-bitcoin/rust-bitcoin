# Changelog

## [Unreleased]

## [0.6.0] - 2026-07-07

### Deletions

- Remove unused or single-use types [#6339](https://github.com/rust-bitcoin/rust-bitcoin/pull/6339)
- Remove the now-unused `hex` dependency [#6490](https://github.com/rust-bitcoin/rust-bitcoin/pull/6490)
- Remove `internals::compact_size` module [#5374](https://github.com/rust-bitcoin/rust-bitcoin/pull/5374)
- Remove the unstable `hex-conservative` dependency [#6148](https://github.com/rust-bitcoin/rust-bitcoin/pull/6148)
- Remove `macros` module [#6340](https://github.com/rust-bitcoin/rust-bitcoin/pull/6340)
- Move `ToU64` to `bitcoin` [#6362](https://github.com/rust-bitcoin/rust-bitcoin/pull/6362)

### Improvements

- Implement `Serialize`/`Deserialize` for `ArrayVec` [#6099](https://github.com/rust-bitcoin/rust-bitcoin/pull/6099)
- Implement `ArrayVec::try_push` [#6193](https://github.com/rust-bitcoin/rust-bitcoin/pull/6193)
- Add `spare_capacity_mut` and `set_len` to `ArrayVec` [#6235](https://github.com/rust-bitcoin/rust-bitcoin/pull/6235)

## [0.5.0] - 2025-12-05

- Remove `doc_auto_cfg` [#5162](https://github.com/rust-bitcoin/rust-bitcoin/pull/5162)
- Move `impl_array_newtype` to `internals` [#5334](https://github.com/rust-bitcoin/rust-bitcoin/pull/5334)

## [0.4.2] - 2025-12-08

Yanking this release because it is on top of the to-be-yanked `v0.4.1`.

- Move `impl_array_newtype` to internals [#5334](https://github.com/rust-bitcoin/rust-bitcoin/pull/5334)

## [0.4.1] - 2024-10-18

This release violated semver rules, sorry - yanking.

- Add `hex-conservative` dependency
- Add `ArrayExt` [#4200](https://github.com/rust-bitcoin/rust-bitcoin/pull/4200)
- Add `compact_size::encoded_size_const` [#2931](https://github.com/rust-bitcoin/rust-bitcoin/pull/2931)
- Add `const_casts` module [#4743](https://github.com/rust-bitcoin/rust-bitcoin/pull/4743)
- Add `transparent_newtype` macro [#4281](https://github.com/rust-bitcoin/rust-bitcoin/pull/4281)
- Move `const_assert` to internals
- Add `SliceExt` [#4182](https://github.com/rust-bitcoin/rust-bitcoin/pull/4182)
- Abstract out "debug-print hex fields" using `WrapDebug` [#4088](https://github.com/rust-bitcoin/rust-bitcoin/pull/4088)

## Breaking changes

This release will be yanked because the following were included and are breaking changes:

- Bump MSRV to Rust 1.74.0 [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/4926)
- Remove usage of `impl_from_infallible` in crates [#3859](https://github.com/rust-bitcoin/rust-bitcoin/pull/3859)
- Removed `impl_array_newtype` [#3544](https://github.com/rust-bitcoin/rust-bitcoin/pull/3544)

## [0.4.0] - 2024-09-18

- Introduce `ToU64` trait [#2929](https://github.com/rust-bitcoin/rust-bitcoin/pull/2929)
- Add macro `impl_to_hex_from_lower_hex ` [#3150](https://github.com/rust-bitcoin/rust-bitcoin/pull/3150)
- Fix bug in `ArrayVec::extend_from_slice` [#3272](https://github.com/rust-bitcoin/rust-bitcoin/pull/3272)
- Introduce `read_push_data_len()` and [#3293](https://github.com/rust-bitcoin/rust-bitcoin/pull/3293/)
- Introduce new `compact_size` module [#3259](https://github.com/rust-bitcoin/rust-bitcoin/pull/3259)

## [0.3.0] - 2024-03-24

- Bump MSRV to Rust version 1.56.1 [#2188](https://github.com/rust-bitcoin/rust-bitcoin/pull/2188)
- Implement custom `ArrayVec` that is `Copy` [#2287](https://github.com/rust-bitcoin/rust-bitcoin/pull/2287)

## 0.2.0 - 2023-06-20

- [Rename crate](https://github.com/rust-bitcoin/rust-bitcoin/pull/1885) to `bitcoin-internals`
- Add module to assist [alloc-free parse error handling](https://github.com/rust-bitcoin/rust-bitcoin/pull/1297)
- Move various macros here.

## 0.1.0 - 2023-03-08

Split this crate out from the [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) crate.
For previous development history see the original
[CHANGELOG](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/CHANGELOG.md) file.

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-internals-0.5.0...HEAD
[0.5.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-internals-0.4.2...bitcoin-internals-0.5.0
[0.4.2]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-internals-0.4.1...bitcoin-internals-0.4.2
[0.4.1]: https://github.com/rust-bitcoin/rust-bitcoin/compare/internals-0.4.0...bitcoin-internals-0.4.1
[0.4.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/internals-0.3.0...internals-0.4.0
[0.3.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-internals-0.2.1...internals-0.3.0
[0.2.1]: https://github.com/rust-bitcoin/rust-bitcoin/compare/bitcoin-internals-0.2.0...bitcoin-internals-0.2.1
