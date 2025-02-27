<div align="center">
  <h1>Rust Bitcoin</h1>

  <img alt="Rust Bitcoin logo by Hunter Trujillo, see license and source files under /logo" src="./logo/rust-bitcoin.png" width="300" />

  <p>Library with support for de/serialization, parsing and executing on data-structures
    and network messages related to Bitcoin.
  </p>

  <p>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
  </p>
</div>

Stable crates released as part of [`rust-bitcoin`](https://crates.io/crates/bitcoin).

- [units](https://crates.io/crates/bitcoin-units)

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.63.0**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

### No-std support

The `std` cargo feature is typically enabled by default. To build these crates without the Rust
standard library, use the `--no-default-features` flag or set `default-features = false` in your
dependency declaration when adding it to your project.

## Release Notes

Release notes are done per crate, see:

- [`units` CHANGELOG](units/CHANGELOG.md)

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
