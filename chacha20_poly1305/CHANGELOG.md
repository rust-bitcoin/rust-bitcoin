# Changelog

## [Unreleased]

## [0.2.1] - 2026-05-04

* Use constant-time equality for Poly1305 tag verification [#6125](https://github.com/rust-bitcoin/rust-bitcoin/pull/6125).
* Upgrade to the stabilized `hex-conservative` dependency, but no public API changes [#6148](https://github.com/rust-bitcoin/rust-bitcoin/pull/6148).

## [0.2.0] - 2026-04-03

* Add fuzzing support [#5854](https://github.com/rust-bitcoin/rust-bitcoin/pull/5854).
* Dropped the `hex_lit` dependency [#5645](https://github.com/rust-bitcoin/rust-bitcoin/pull/5645).
* Add common trait implementations [#5605](https://github.com/rust-bitcoin/rust-bitcoin/pull/5605).
* Bumped the MSRV to 1.74 [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/4926).

## [0.1.2] - 2025-05-15

* Fixed a bug which was doubling the amount of work, performance should be improved [#4083](https://github.com/rust-bitcoin/rust-bitcoin/pull/4083).

## [0.1.1] - 2024-11-07

* The crate is now `no_std`.

## 0.1.0 - 2024-10-28

* Initial release to create the chacha20-poly1305 crate.

[Unreleased]: https://github.com/rust-bitcoin/rust-bitcoin/compare/chacha20-poly1305-0.2.1...HEAD
[0.2.1]: https://github.com/rust-bitcoin/rust-bitcoin/compare/chacha20-poly1305-0.2.0...chacha20-poly1305-0.2.1
[0.2.0]: https://github.com/rust-bitcoin/rust-bitcoin/compare/chacha20-poly1305-0.1.2...chacha20-poly1305-0.2.0
[0.1.2]: https://github.com/rust-bitcoin/rust-bitcoin/compare/chacha20-poly1305-0.1.1...chacha20-poly1305-0.1.2
[0.1.1]: https://github.com/rust-bitcoin/rust-bitcoin/compare/chacha20-poly1305-0.1.0...chacha20-poly1305-0.1.1
