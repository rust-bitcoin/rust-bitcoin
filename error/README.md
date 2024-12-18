<div align="center">
  <h1>no-std-error</h1>

  <p>Error handling tools for code that is expected to work in both `std` and `no_std` environments.
  </p>

  <p>
    <a href="https://crates.io/crates/no-std-error"><img alt="Crate Info" src="https://img.shields.io/crates/v/no-std-error.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/blob/master/LICENSE"><img alt="CC0 1.0 Universal Licensed" src="https://img.shields.io/badge/license-CC0--1.0-blue.svg"/></a>
    <a href="https://github.com/rust-bitcoin/rust-bitcoin/actions?query=workflow%3AContinuous%20integration"><img alt="CI Status" src="https://github.com/rust-bitcoin/rust-bitcoin/workflows/Continuous%20integration/badge.svg"></a>
    <a href="https://docs.rs/no-std-error"><img alt="API Docs" src="https://img.shields.io/badge/docs.rs-no-std-error-green"/></a>
    <a href="https://blog.rust-lang.org/2021/11/01/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
  </p>
</div>

Provides:

- A `write_err!` macro that gracefully handles the error `source` in both `std` and `no_std`.
- An `InputString` type that can be used as part of an error type when parsing strings and still
  work in environments without an allocator.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features on **Rust 1.63.0**.

Use `Cargo-minimal.lock` to build the MSRV by copying to `Cargo.lock` and building.

## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
