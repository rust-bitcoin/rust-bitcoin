# Rust Bitcoin - Shared Macros

This directory holds shared source code that can be used in any of the crates through the
[`include!`] macro. Generally files in this directory are written such that their content can be
included once at the top level of a crate (e.g. in `lib.rs`), and then used throughout, rather than
calling [`include!`] at each usage site.

The intent is to follow the DRY principle for code that needs to be re-used across crates without
creating a dedicated helper crate, which would add another dependency and can complicate
visibility, trait impl placement/coherence, and general API surface management.

## Conventions

* Each file is included once at a stable module boundary in the consuming crate (often `lib.rs`,
  but sometimes an internal module such as `internal_macros.rs` or `pow.rs`), rather than at every
  usage site.
* Included items live in the namespace of the module that performs the `include!` and inherit that
  module's visibility rules.

## Usage

Pull a file in once at a stable location, typically near the top of `lib.rs`:

```rust,ignore
include!("../include/newtype.rs");
include!("../include/decoder_newtype.rs");
```

After that, the macros / items defined inside are usable exactly as if they had been written at the
inclusion site directly. If the file is included in a module, they live in that module unless
re-exported.

[`include!`]: https://doc.rust-lang.org/std/macro.include.html
