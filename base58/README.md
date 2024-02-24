Bitcoin base58 encoding
=======================

This crate provides encoding and decoding of base58 strings as defined by the Bitcoin ecosystem
including the checksum.

There are two other crates on crates.io that implement base58 encoding and decoding. This
crate differs from them because:

1. [bitcoin-base58](https://crates.io/crates/bitcoin-base58) is transpiled from the C++ code in
   Bitcoin Core as part of a large long-term transpilation project; this crate is a pure Rust
   implementation intended to be production-ready and to provide an Rust-idiomatic API.

2. [base58](https://crates.io/crates/base58) is incomplete and appears unmaintained as of
   February 2024. It does not validate checksums and will therefore accept invalid Bitcoin
   addresses. It may be appropriate in cases where performance is more important than safety.


## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.56.1**.


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).
