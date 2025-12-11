# Bitcoin base58 encoding

This crate provides encoding and decoding of base58 strings as defined by the Bitcoin ecosystem
including the checksum.

There are a bunch of crates on crates.io that implement base58 encoding and decoding. The more
obviously named ones differ from this crate because:

1. [bitcoin-base58](https://crates.io/crates/bitcoin-base58) is transpiled from the C++ code in
   Bitcoin Core as part of a large long-term transpilation project, whereas this crate is a pure
   Rust implementation intended to be production-ready and to provide an Rust-idiomatic API.

2. [base58](https://crates.io/crates/base58) implements parsing but does not validate checksums (see
   `base58check`). It may be appropriate in cases where performance is more important than safety.
   Appears unmaintained.

3. [base58check](https://crates.io/crates/base58check) Adds checksum to the `base58` crate and
   depends on [sha2](https://crates.io/crates/sha2/0.8.2) for hashing. Appears unmaintained.

This crate uses [bitcoin_hashes](https://crates.io/crates/bitcoin_hashes) when hashing to calculate
the checksum.
