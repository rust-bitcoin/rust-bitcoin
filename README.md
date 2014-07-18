
### Rust Bitcoin Library

This library is badly incomplete --- though at this point it is perhaps stable
enough that pull requests could be accepted.

Currently development is following the needs of the
[Wizard's Wallet](https://github.com/apoelstra/wizards-wallet), which is
a "lite" wallet which does SPV validation but maintains a full UTXO index.
Its purpose is to be a usable-though-risky wallet which supports experimental
user-facing features.

Pull requests to generalize the library or introduce new use cases would
be great.

### Building

To build, start by obtaining [cargo](http://crates.io/). Then just run `cargo build`.
To run the test cases, do `cargo test`. Note that the tests must pass (and reasonably
complete unit tests provided for new features) before any submissions can be accepted.



