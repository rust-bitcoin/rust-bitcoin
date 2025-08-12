# rust-bitcoin stack of crates

The `rust-bitcoin` project is in the, very long, process of crate
smashing. The original single `rust-bitcoin` crate has already been
broken into a number of pieces and this work is ongoing. Both current
and future crates are documented here. Future crates typically have an
entry in [roadmap.md] and likely also a file of their own.

## Current crates

- `addresses`: **Empty** placeholder (see future crates below).
- `base58`: Bitcoin base58 encoding and decoding (for pre-segwit addresses).
- `bitcoin`: The `rust-bitcoin` crate.
- `chacha20_poly135`: ChaCha20 stream cipher with the Poly1305 MAC.
- `hashes`: Rust Bitcoin hashes library.
- `internals`: Used internally by crates in this repo.
- `io`: Rust Bitcoin I/O library (to support `no_std`).
- `p2p`: Rust Bitcoin peer to peer message types.
- `primitives`: Rust Bitcoin primitive types.
- `units`: Rust Bitcoin unit types.

### Crates in our stack but in different repositories

A few crates are in different repositories, primarily because they were either started by different
people or they have a (slightly) different set of maintainers and/or merge policy.

- `secp256k1`: https://github.com/rust-bitcoin/rust-secp256k1
- `bech32`: https://github.com/rust-bitcoin/rust-bech32
- `hex-conservative`: https://github.com/rust-bitcoin/hex-conservative
- `miniscript`: https://github.com/rust-bitcoin/rust-miniscript

## Future crates

- `addresses`: Bitcoin addresses (see [address.md])
- `bip-32`: BIP-32 (and maybe BIP-380) support (see [bip-32.md])
- `psbt`: PSBTv2 support (see [psbt.md])
- `keys`: Public and private Bitcoin keys (see [keys.md])
- ``

## Re-export policy

Any crate `foo` which exposes a type from crate `bar` MUST publicly re-export `bar` crate at the root.

Furthermore, `bitcoin`, `primitives`, and `units` should each be a superset of the crates below. E.g
for any `units::Foo`, there will be a `primitives::Foo`, and `bitcoin::Foo`. This goes for all
types and modules. For these three crates, non-error re-exports use `doc(inline)`.

### Doc inlining types and errors

- Error types that are directly in the API are re-exported.
- Other error types are available in an error module.
- Error re-exports use `doc(no_inline)`.

E.g

In `units`

```rust

pub mod foo {
    // SomeError is 'directly' in the API but FooError is not.
    pub use self::error::SomeError;

    /// A FooBar type.
    pub struct FooBar { ... };

    /// Some function.
    pub some_function() -> SomeError { 
        // Example rror logic
        SomeError::Foo(FooError { ... })
    }
    
    pub mod error {
        /// Example error used 'directly' in the public API.
        pub enum SomeError { ... };
    
        /// Abstracts the details of a foo-related error.
        pub struct FooError { ... };
    }
}
```

In `primitives` (and in `bitcoin`) in `lib.rs`
```rust
#[doc(inline)]
pub use units::{foo, FooBar};
#[doc(no_inline)]
pub use units::foo::SomeError;
```


[addresses.md]: ./addresses.md
[bip-32.md]: ./bip-32.md
[keys.md]: ./keys.md
[psbt.md]: ./psbt.md
