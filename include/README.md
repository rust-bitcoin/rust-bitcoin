# Rust Bitcoin - Shared Macros

This directory holds shared source code that can be used in any of the crates through the
[`include!`] macro. Generally files in this directory are written such that their content can be
included once at the top level of a crate (e.g. in `lib.rs`), and then used throughout, rather than
calling [`include!`] at each usage site.

The intent is to follow the DRY principle for code that needs to be reused across crates without
creating a dedicated helper crate (we previously explored this with `bitcoin-internals`, and are now
moving macros out of it. See PR [#6231]).

## Conventions

* Each file is included once at a stable module boundary in the consuming crate (often `lib.rs`,
  but sometimes an internal module such as `internal_macros.rs` or `pow.rs`), rather than at every
  usage site.
* Included items live in the namespace of the module that performs the `include!` and inherit that
  module's visibility rules.

[`include!`]: https://doc.rust-lang.org/std/macro.include.html
[#6231]: https://github.com/rust-bitcoin/rust-bitcoin/pull/6231
