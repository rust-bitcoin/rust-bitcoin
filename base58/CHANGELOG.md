# Changelog

## [Unreleased]

## [0.4.0] - 2025-01-08

- Update to latest `hashes 0.20.0`

## [0.3.0] - 2025-12-15

- Bump MSRV from 1.63.0 to 1.74.0 for all crates in the repo [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/4926)

## [0.2.0] - 2024-12-10

- Bump MSRV to `1.63` [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
- Optimize `base58` on small inputs [#3002](https://github.com/rust-bitcoin/rust-bitcoin/pull/3002)
- Add `alloc` feature [#2996](https://github.com/rust-bitcoin/rust-bitcoin/pull/2996)
- Remove zeroed vector by pushing front [#3227](https://github.com/rust-bitcoin/rust-bitcoin/pull/3227)
- Close all errors [#3533](https://github.com/rust-bitcoin/rust-bitcoin/pull/3533)
- Bump `hex-conservative` to `0.3.0` [#3543](https://github.com/rust-bitcoin/rust-bitcoin/pull/3543)

## [0.1.100] - 2026-05-27

- Bump MSRV to Rust 1.74.0 [#6126](https://github.com/rust-bitcoin/rust-bitcoin/pull/6126)

> Note the version number jump. We jumped to `v0.1.100` when doing the MSRV bump so as to leave room for a bunch of secuity releases up to this number if needed

## [0.1.1] - 2026-05-23

- Remove `internals` dependency [#6200](https://github.com/rust-bitcoin/rust-bitcoin/pull/6200)

## 0.1.0 - 2024-03-14

Initial release of the `base58ck` crate. This crate was cut out of
`rust-bitcoin` and cleaned up for release as a separate crate.

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.4.0...HEAD
[0.4.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.3.0...base58ck-0.4.0
[0.3.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.2.0...base58ck-0.3.0
[0.2.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.1.100...base58ck-0.2.0
[0.1.100]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.1.1...base58ck-0.1.100
[0.1.1]: https://github.com/rust-bitcoin/rust-bitcoin/compare/base58ck-0.1.0...base58ck-0.1.1
