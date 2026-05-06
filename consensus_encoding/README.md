# Bitcoin Consensus Encoding

Sans-IO encoding and decoding support used by the `rust-bitcoin` ecosystem for objects that have a
consensus-specified byte encoding.

## History

Historically `rust-bitcoin` supported consensus encoding/decoding by way of the
[`bitcoin::consensus`](https://docs.rs/bitcoin/0.32.0/bitcoin/consensus/) module. This code
included the `std::io::Error` type which turned out to be the cause of a lot of pain, including
but not restricted to, creation of the [`bitcoin_io`](https://crates.io/crates/bitcoin-io) crate.

The solution was to re-write the consensus encoding/decoding logic using the sans-IO paradigm.

As part of developing this crate we fuzz against the latest `bitcoin 0.32` release. If interested
see `rust-bitcoin/fuzz/fuzz_targets/bitcoin/compare_consensus_encoding.rs`.
