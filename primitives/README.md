# Rust Bitcoin - primitive types.

This crate provides primitive data types that are used throughout the
[`rust-bitcoin`](https://github.com/rust-bitcoin) ecosystem.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported, and we can't promise they will be. If you care about them
please let us know, so we can know how large the interest is and possibly decide to support them.

## Semver compliance

Functions marked as unstable (e.g. `foo__unstable`) are not guaranteed to uphold semver compliance.
They are primarily provided to support `rust-bitcoin`.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.74.0**.

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](../LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
