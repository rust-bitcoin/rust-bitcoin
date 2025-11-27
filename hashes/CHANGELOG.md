# 0.18.0 - 2025-11-27

* Add a dependency on the new `consensus_encoding` crate [#5181](https://github.com/rust-bitcoin/rust-bitcoin/pull/5181)

# 0.17.0 - 2025-10-17

* Bump MSRV from 1.63.0 to 1.74.0 for all crates in the repo [#4926](https://github.com/rust-bitcoin/rust-bitcoin/pull/4926)
* Add a `sha3_256` module with `SHA3-256` [#4919](https://github.com/rust-bitcoin/rust-bitcoin/pull/4919)
* Remove code deprecated in `v0.15.0` [#4840](https://github.com/rust-bitcoin/rust-bitcoin/pull/4840)
* Update `serde` dependency to match workspace [#4321](https://github.com/rust-bitcoin/rust-bitcoin/pull/4321)
* Remove `From<hash>` for not-general-hash types [#4128 ](https://github.com/rust-bitcoin/rust-bitcoin/pull/4128)
* Remove the `GeneralHash` trait [#4085](https://github.com/rust-bitcoin/rust-bitcoin/pull/4085)
* Only enable `hex`/`std`, and `hex`/`alloc` when `hex` is [#4055](https://github.com/rust-bitcoin/rust-bitcoin/pull/4055)
* Derive `Debug` for all hash engines [#4015](https://github.com/rust-bitcoin/rust-bitcoin/pull/4015)
* Add a tagged hash engine [#4010](https://github.com/rust-bitcoin/rust-bitcoin/pull/4010)
* Add engine function to `siphash24::Hash` [#4003](https://github.com/rust-bitcoin/rust-bitcoin/pull/4003)
* Do not implement `Default` for `HmacEngine` [#3981](https://github.com/rust-bitcoin/rust-bitcoin/pull/3981)
* Invert dependency between `io` and `hashes` [#3961](https://github.com/rust-bitcoin/rust-bitcoin/pull/3961)

# 0.16.0 - 2024-12-12

* Make `hex-conservative` an optional dependency [#3611](https://github.com/rust-bitcoin/rust-bitcoin/pull/3611)
* Bump `hex-conservative` to `v0.3.0` [#3543](https://github.com/rust-bitcoin/rust-bitcoin/pull/3543)
* Hide error internals [#3579](https://github.com/rust-bitcoin/rust-bitcoin/pull/3579)

# 0.15.0 - 2024-10-16

This release is massive. The biggest visible changes are to the `Hash` trait, which has mostly been replaced
by inherent functions. You should not need to import it at all anymore for normal usage. Check out how we are
using `hashes` in `rust-bitcoin` to see an example. Enjoy!

* Remove the `util` and `serde_macros` modules and roll all code into new public `macros` module [#3299](https://github.com/rust-bitcoin/rust-bitcoin/pull/3299)
* Remove `SliceIndex` implementation from hash types [#3296](https://github.com/rust-bitcoin/rust-bitcoin/pull/3296)
* Rename `Midstate::into_parts` to `Midstate::to_parts` since it derives `Copy` [#3429](https://github.com/rust-bitcoin/rust-bitcoin/pull/3429)
* Remove `schemars` support [#3395](https://github.com/rust-bitcoin/rust-bitcoin/pull/3395)
* Deprecate `from_slice` methods in favor of arrays [#3301](https://github.com/rust-bitcoin/rust-bitcoin/pull/3301)
* Rename `length` field to `bytes_hashed` [#3298](https://github.com/rust-bitcoin/rust-bitcoin/pull/3298)
* Enforce that `Hash::Bytes` is an array [#3257](https://github.com/rust-bitcoin/rust-bitcoin/pull/3257)
* `Siphash24` cleanup [#3222](https://github.com/rust-bitcoin/rust-bitcoin/pull/3222)
* Reduce API surface of tagged wrapped hash types [#3184](https://github.com/rust-bitcoin/rust-bitcoin/pull/3184)
* Rename `const_hash` functions to `hash_unoptimized` [#3129](https://github.com/rust-bitcoin/rust-bitcoin/pull/3129)
* Remove `io` feature (use `bitcoin-io` dependency directly) [#3128](https://github.com/rust-bitcoin/rust-bitcoin/pull/3128)
* Rename `Siphash::as_u64` to `Siphash::to_u64` [#3119](https://github.com/rust-bitcoin/rust-bitcoin/pull/3119)
* Push up the `Default` bound on `HashEngine` in order to better support keyed hash functions [#3113](https://github.com/rust-bitcoin/rust-bitcoin/pull/3113)
* Add a new `hash_reader` function [#3077](https://github.com/rust-bitcoin/rust-bitcoin/pull/3077)
* Add `length` field to `sha256::Midstate` [#3010](https://github.com/rust-bitcoin/rust-bitcoin/pull/3010)
* Remove midstate from the `GeneralHash` and `HashEngine` traits [#3009](https://github.com/rust-bitcoin/rust-bitcoin/pull/3009)
* Add additional `HashEngine` types [#2988](https://github.com/rust-bitcoin/rust-bitcoin/pull/2988)
* Remove `to`/`from`/`as_raw_hash` functions [#2981](https://github.com/rust-bitcoin/rust-bitcoin/pull/2981)
* Split `Hash` trait into `GeneralHash` and `Hash` [#2910](https://github.com/rust-bitcoin/rust-bitcoin/pull/2910)
* Remove `all_zeros` and constify constructors [#2877](https://github.com/rust-bitcoin/rust-bitcoin/pull/2877)
* Add inherent functions to hashes (reduces need to import `Hash`) [#2852](https://github.com/rust-bitcoin/rust-bitcoin/pull/2852)
* Add HKDF support [#2644](https://github.com/rust-bitcoin/rust-bitcoin/pull/2644)
* Bump MSRV to Rust version 1.63.0 [#3100](https://github.com/rust-bitcoin/rust-bitcoin/pull/3100)
* Change the default display direction of for tagged hashes to forwards [#2707](https://github.com/rust-bitcoin/rust-bitcoin/pull/2707)

  Note please this usage if you need to display backward:

```rust
  sha256t_hash_newtype! {
    /// Test detailed explanation.
    struct NewTypeTag = hash_str("tag");

    /// A test hash.
    #[hash_newtype(backward)]
    struct NewTypeHash(_);
  }
```

# 0.14.0 - 2024-03-21

* Bump MSRV to Rust version 1.56.1 [#2188](https://github.com/rust-bitcoin/rust-bitcoin/pull/2188)

## API improvements

* Add support for SHA384 [#2538](https://github.com/rust-bitcoin/rust-bitcoin/pull/2538)
* Make from_hex inherent for byte-like types [#2491](https://github.com/rust-bitcoin/rust-bitcoin/pull/2491)
* Add `Hash::from_bytes_iter` to construct hashes from iterators [#2272](https://github.com/rust-bitcoin/rust-bitcoin/pull/2272)
* Make some constructors `const` [#2446](https://github.com/rust-bitcoin/rust-bitcoin/pull/2446)

## Features/dependencies changes

* Removed `core2` dependency in favour of the new `bitcoin-io` crate [#2066](https://github.com/rust-bitcoin/rust-bitcoin/pull/2066)
* Remove "serde-std" [#2384](https://github.com/rust-bitcoin/rust-bitcoin/pull/2384)

## Error handling improvements

* Improve leaf errors [#2530](https://github.com/rust-bitcoin/rust-bitcoin/pull/2530)
* Implement `From<Infallible>` for errors [#2516](https://github.com/rust-bitcoin/rust-bitcoin/pull/2516)

# 0.13.0 - 2023-06-29

The main improvement in this version is removal of the `hex` module in favour of the new
[`hex-conservative`](https://crates.io/crates/hex-conservative) crate (which we wrote). We also
bumped the Minimum Supported Rust Version across the `rust-bitcoin` ecosystem to v1.48

* Bump MSRV to 1.48.0 [#1729](https://github.com/rust-bitcoin/rust-bitcoin/pull/1729).
* Depend on new `hex-conservative` crate and remove `hex` module [#1883](https://github.com/rust-bitcoin/rust-bitcoin/pull/1833).
* Make `sha256t_hash_newtype!` evocative of the output [#1773](https://github.com/rust-bitcoin/rust-bitcoin/pull/1773).
* Implement computing SHA256 in const context [#1769](https://github.com/rust-bitcoin/rust-bitcoin/pull/1769).
* Add `from_bytes_ref` and `from_bytes_mut` to all hash types [#1761](https://github.com/rust-bitcoin/rust-bitcoin/pull/1761).
* Rename `crate::Error` to `crate::FromSliceError` [#1873](https://github.com/rust-bitcoin/rust-bitcoin/pull/1873).
* Add simd sha256 intrinsics for x86 machines [#1962](https://github.com/rust-bitcoin/rust-bitcoin/pull/1962).
* Introduce the "small-hash" feature for `bitcoin_hashes` [#1990](https://github.com/rust-bitcoin/rust-bitcoin/pull/1990).

# 0.12.0 - 2023-03-05

0.12 is a significant release. We pulled the repository into the rust-bitcoin
repo to improve our integration testing and to get more eyes on this crate. We
began the process of replacing the hex functionality in this crate with a more
performant, dedicated crate, and otherwise cleaning up the API as we look forward
to 1.0.

* [Remove `FromHex` implementation](https://github.com/rust-bitcoin/rust-bitcoin/pull/1565/commits/a308e1e2ea5c6ae419d961b8da71cc8a35a92715)
from all hashes and implement `FromStr` instead.
* Move crate from [original repo](https://github.com/rust-bitcoin/bitcoin_hashes) to the
`rust-bitcoin` repository. Commit history was lost during move, for commit history see the original
repository. Tip of bitcoin_hashes:master at time of import: 54c16249e06cc6b7870c7fc07d90f489d82647c7
* [Remove `Deref` impls for all hashes](https://github.com/rust-bitcoin/rust-bitcoin/pull/1450)
* [Add `AsRef` impls for all hashes from fixed-size arrays](https://github.com/rust-bitcoin/rust-bitcoin/pull/1593)
* [Add the `sha512_256` hash](https://github.com/rust-bitcoin/rust-bitcoin/pull/1413)
* [Remove the `ToHex` trait in favor of `DisplayHex` and `fmt::Display`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1531)
* [Remove the now-unused `HexWriter` object](https://github.com/rust-bitcoin/rust-bitcoin/pull/1572)
* [nostd: `alloc` feature no longer enables `core2`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1612)
* [Rewrite `hash_newtype` macro with new syntax](https://github.com/rust-bitcoin/rust-bitcoin/pull/1659)
* [Rename `Hash::Inner` to `Hash::Bytes`, 'Hash::*_inner` and several related conversion methods](https://github.com/rust-bitcoin/rust-bitcoin/pull/1577)


# 0.11.0 - 2022-06-25

The major change in this version is the increase of the Minimum Supported Rust Version (MSRV) from
1.29 to 1.41.1. This is a big change because it introduces Rust Edition 2018 to the codebase along
with all the benefits that brings. We also did a bunch of optimisations to speed up encoding and
decoding hex strings.

## Breaking changes

* [Enable edition 2018 and bump MSRV to Rust 1.41.1](https://github.com/rust-bitcoin/bitcoin_hashes/pull/136)

## New features/APIs

* [Add `all_zeros` to `Hash` trait](https://github.com/rust-bitcoin/bitcoin_hashes/pull/148)
* [Implement `Write` on `HmacEngine`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/133)
* [Introduce `HexWriter`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/156), makes serialising hex faster
* [Implement `Read` on `HexIterator`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/135), makes deserialising hex faster

## Other improvements

* Use `rotate_left` [instead of custom macro](https://github.com/rust-bitcoin/bitcoin_hashes/pull/162)
* [Enable clippy on CI](https://github.com/rust-bitcoin/bitcoin_hashes/pull/152)
* Various docs fixes
* [Improve feature test coverage](https://github.com/rust-bitcoin/bitcoin_hashes/pull/147)
* [Add a disabled `rustfmt.toml`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/141) to improve interaction with auto-formatting in editors


# 0.10.0 - 2021-07-05

* Increase `core2` to released version of 0.3.0

# 0.9.7 - 2021-06-17

* Introduce `alloc` feature and `core2` dependency for nostd support (this feature has MSRV of 1.36 rather than 1.29)

# 0.9.6 - 2021-05-03

* Re-export `core` as `_export::_core`. This resolves an issue when calling several exported macros with the `std` feature.

# 0.9.5 - 2021-04-28

* Add [`#[repr(transparent)]` to all newtype wrappers](https://github.com/rust-bitcoin/bitcoin_hashes/pull/108/)
* Add [missing `#derive`s](https://github.com/rust-bitcoin/bitcoin_hashes/pull/110/)
* Replace `fuzztarget` feature with [use of `cfg(fuzzing)`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/111/)
* Use [`core` rather than `std`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/118/) and [fix `no_std` compilation](https://github.com/rust-bitcoin/bitcoin_hashes/pull/122/)

Note that we have stopped re-exporting the `core` crate when compiling without `std`. This is technically a breaking change but it is hard to imagine what user might be affected.

# 0.9.4 - 2020-10-23

* Add `Hmac::from_inner_engines`

# 0.9.3 - 2020-10-19

* More serde macro fixes

# 0.9.2 - 2020-10-18

* Fix rustc 1.29.0 downstream issues with serde macros

# 0.9.2 - 2020-10-16

* Fix visibility issue with serde macros

# 0.9.1 - 2020-10-07

* Add `FromStr` impl to `sha256t::Hash`
* Fix `Hash::engine()` implementation for hash newtypes
* Add `sha256t_hash_newtype!` macro for creating tagged hashes

# 0.9.0 - 2020-08-27

* **Update MSRV to 1.29.0**

# 0.8.0 - 2020-08-26

* Add `as_inner` method to `Hash` trait
* Add `n_bytes_hashed` to `HashEngine` trait

# 0.7.6 - 2020-04-05

* Support hash newtypes with reversed hex serialization.

# 0.7.5 - 2020-04-02

* Add `sha256t` module for SHA-256-based tagged hashes.
* Add `FromStr` for hash newtypes.
* Add `from_hash` for hash newtypes.

# 0.7.3 - 2019-12-18

* Add `as_hash(&self) -> <inner>` method to hash newtypes.

# 0.7.2 - 2019-11-29

* Make the inner variable of `sha256::Midstat` public
* Drop the `byteorder` dependency in favor of manual endianness implementations
(later this will be in stdlib so we can drop even that)
* Fix the `hash_newtype` macro, which did not compile before

# 0.7.1 - 2019-08-14

* Add hash_newtype macro that allows third parties to create newtype structs.

# 0.7.0 - 2019-07-19

* Add `hex::Error` type for errors generated by the `hex` module.

# 0.6.0 - 2019-07-10

* Add `no_std` support, rearrange traits to not depend on `io::Write`

# 0.5.0 - 2019-06-28

* Fix panic when parsing hashes that contain multibyte characters
* Add `FromStr` to all hashes which hex-parses them

# 0.4.0 - 2019-06-23

* [Add `from_inner` method](https://github.com/rust-bitcoin/bitcoin_hashes/pull/20) to all hashes
* [Update `FromHex` trait](https://github.com/rust-bitcoin/bitcoin_hashes/pull/40) to require `from_byte_iter` method rather than `from_hex` be implemented
* Make `Hmac` midstate [an actual HMAC midstate](https://github.com/rust-bitcoin/bitcoin_hashes/pull/43)
* Allow `Display` [of truncated hashes](https://github.com/rust-bitcoin/bitcoin_hashes/pull/9)
* Require [using a constructor for `HexIterator`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/44) and then [clean up the internals](https://github.com/rust-bitcoin/bitcoin_hashes/pull/47)
* [Strongly type `sha256::Midstate`](https://github.com/rust-bitcoin/bitcoin_hashes/pull/39) to allow independent serialization
* Add [siphash24 module](https://github.com/rust-bitcoin/bitcoin_hashes/pull/46)

# 0.3.2 - 2019-03-20

* Implement the `FromHex` trait on [many more types](https://github.com/rust-bitcoin/bitcoin_hashes/pull/38)

# 0.3.1 - 2019-03-04

* [Fix serde serialization](https://github.com/rust-bitcoin/bitcoin_hashes/pull/36)

# 0.3.0 - 2019-01-23

* Bump minimum required rustc version to 1.22.0
* Fixed serde deserialization into owned string that previously caused panics
  when doing round-trip (de)serialization
* `HashEngine::block_size()` and `Hash::len()` are now associated constants
  `HashEngine::BLOCK_SIZE` and `Hash::LEN`
* Removed `block_size()` method from `Hash` trait. It is still available as
  `<T as Hash>::Engine::BLOCK_SIZE`

# 0.2.0 - 2019-01-15

* Add a constant-time comparison function
* Simplify `io::Write::write` implementations by having them do only partial writes
* Add fuzzing support
* Allow `Hash`es to be borrowed as `[u8]`
* Replace public `Hash` inners with `into_inner` method

# 0.1.0 - 2018-12-08

* Initial release
