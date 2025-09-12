
# Coding policy for the rust-bitcoin repository

We have various `rust-bitcoin` specific coding styles and conventions that are
grouped here loosely under the term 'policy'. These are things we try to adhere
to but that you should not need to worry too much about if you are a new
contributor. Think of this as a place to collect group knowledge that exists in
the various PRs over the last few years.

## Import statements

We use the following style for import statements, see
(https://github.com/rust-bitcoin/rust-bitcoin/discussions/2088) for the discussion that led to this.

```rust
// Modules first, as they are part of the project's structure.
pub mod aa_this;
mod bb_private;
pub mod cc_that;

// Private imports, rustfmt will sort and merge them correctly.
use crate::aa_this::{This, That};
use crate::bb_that;

// Public re-exports.
#[rustfmt::skip] // Keeps public re-exports separate, because of this we have to sort manually.
pub use {
    crate::aa_aa_this,
    crate::bb_bb::That,
}

// Avoid wildcard imports, except for 3 rules:

// Rule 1 - test modules.
#[cfg(test)]
mod tests {
    use super::*; // OK
}

// Rule 2 - enum variants.
use LockTime::*; // OK

// Rule 3 - opcodes.
use opcodes::all::*; // OK

// Finally here is an example where we don't allow wildcard imports:
use crate::prelude::*; // *NOT* OK
use crate::prelude::{DisplayHex, String, Vec} // OK
```

## Re-exports

Types should _not_ be re-exported unless it is _really_ helpful. I.e., we considered re-exporting
types from modules where they appear in the public API but decided against it.

### pub extern crates

Any crate `foo` which exposes a type from crate `bar` MUST publicly re-export `bar` crate at the
root.


For example:

```rust
/// Re-export the `hex-conservative` crate.
pub extern crate hex;
```

Note, can use this exact doc format.

### Special treatment of `bitcoin`, `primitives`, `units`

`bitcoin`, `primitives`, and `units` should each be a superset of the crates below.

E.g for any `units::Foo`, there will be a `primitives::Foo`, and `bitcoin::Foo`. This goes for all
types and modules.

For these three crates:

- Non-error re-exports use `doc(inline)`.
- Error re-exports use `doc(no_inline)`.
- Error types that are directly in the API are re-exported.
- Other error types are available in an `error` module.

For example in `units`:

```rust

pub mod foo {
    // SomeError is 'directly' in the API but FooError is not.
    pub use self::error::SomeError;

    /// A FooBar type.
    pub struct FooBar { ... };

    /// Some function.
    pub some_function() -> SomeError {
        // Example error logic
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

Then in `primitives` (and in `bitcoin`) in `lib.rs`:

```rust
#[doc(inline)]
pub use units::{foo, FooBar};
#[doc(no_inline)]
pub use units::foo::SomeError;
```

### Usage of re-exports

As part of the attempt to mirror the `units` and `primitives`, and `bitcoin` APIs, in this codebase,
policy is to use types from the highest crate available i.e `use crate::Foo` not `units::Foo`.

This is enforced by CI.

## Return `Self`

Use `Self` as the return type instead of naming the type. When constructing the return value use
`Self` or the type name, whichever you prefer.

```rust
/// A counter that is always smaller than 100.
pub struct Counter(u32);

impl Counter {
    /// Constructs a new `Counter`.
    pub fn new() -> Self { Self(0) }

    /// Returns a counter if it is possible to create one from x.
    pub fn maybe(x: u32) -> Option<Self> {
        match x {
            x if x >= 100 => None,
            c => Some(Counter(c)),
        }
    }
}

impl TryFrom<u32> for Counter {
    type Error = TooBigError;

    fn try_from(x: u32) -> Result<Self, Self::Error> {
        if x >= 100 {
            return Err(TooBigError);
        }
        Ok(Counter(x))
    }
}
```

When constructing the return value for error enums use `Self`.

```rust
impl From<foo::Error> for LongDescriptiveError {
    fn from(e: foo::Error) -> Self { Self::Foo(e) }
}
```

## Errors

Return as much context as possible with errors e.g., if an error was encountered parsing a string
include the string in the returned error type. If a function consumes costly-to-compute input
(allocations are also considered costly) it should return the input back in the error type.

More specifically an error should

- be `non_exhaustive` unless we _really_ never want to change it.
- have private fields unless we are very confident they won't change.
- derive `Debug, Clone, PartialEq, Eq` (and `Copy` if and only if not `non_exhaustive`).
- implement Display using `write_err!()` macro if a variant contains an inner error source.
- have `Error` suffix on error types (structs and enums).
- not have `Error` suffix on enum variants.
- call `internals::impl_from_infallible!`.
- implement `std::error::Error` if they are public (feature gated on "std").
- have messages in lower case, except for proper nouns and variable names.

```rust
/// Documentation for the `Error` type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]  // Add liberally; if the error type may ever have new variants added.
pub enum Error {
    /// Documentation for variant A.
    A,
    /// Documentation for variant B.
    B,
}

internals::impl_from_infallible!(Error);

```

All errors that live in an `error` module (eg, `foo/error.rs`) and appear in a public function in
`foo` module should be available from `foo` i.e., should be re-exported from `foo/mod.rs`.

## `expect` messages

With respect to `expect` messages, they should follow the
[Rust standard library guidelines](https://doc.rust-lang.org/std/option/enum.Option.html#recommended-message-style).
More specifically, `expect` messages should be used to describe the reason
you expect the operation to succeed.
For example, this `expect` message clearly states why the operation should succeed:

```rust
/// Serializes the public key to bytes.
pub fn to_bytes(self) -> Vec<u8> {
    let mut buf = Vec::new();
    self.write_into(&mut buf).expect("vecs don't error");
    buf
}
```

Also note that `expect` messages, as with all error messages, should be lower
case, except for proper nouns and variable names.

<details>
<summary>The details on why we chose this style</summary>

According to the [Rust standard library](https://doc.rust-lang.org/std/error/index.html#common-message-styles),
there are two common styles for how to write `expect` messages:

- using the message to present information to users encountering a panic
  ("expect as error message"); and
- using the message to present information to developers debugging the panic
  ("expect as precondition").

We opted to use the "expect as precondition" since it clearly states why the
operation should succeed.
This may be better for communicating with developers, since they are the target
audience for the error message and `rust-bitcoin`.

If you want to know more about the decision error messages and expect messages,
please check:

- https://github.com/rust-bitcoin/rust-bitcoin/issues/2913
- https://github.com/rust-bitcoin/rust-bitcoin/issues/3053
- https://github.com/rust-bitcoin/rust-bitcoin/pull/3019
</details>

## Rustdocs

Be liberal with references to BIPs or other documentation; the aim is that devs can learn about
Bitcoin by hacking on this codebase as opposed to having to learn about Bitcoin first and then start
hacking on this codebase. Consider the following format, not all sections will be required for all types.


```rust
/// The Bitcoin foobar.
///
/// Contains all the data used when passing a foobar around the Bitcoin network.
///
/// <details>
/// <summary>FooBar Original Design</summary>
///
/// The foobar was introduced in Bitcoin x.y.z to increase the amount of foo in bar.
///
/// </details>
///
/// ### Relevant BIPs
///
/// * [BIP-XXXX - FooBar in Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-xxxx.mediawiki)
pub struct FooBar {
    /// The version in use.
    pub version: Version
}
```

Do use rustdoc subheadings. Do put an empty newline below each heading e.g.,

```rust
impl FooBar {
    /// Constructs a `FooBar` from a [`Baz`].
    ///
    /// # Errors
    ///
    /// Returns an error if `Baz` is not ...
    ///
    /// # Panics
    ///
    /// If the `Baz`, converted to a `usize`, is out of bounds.
    pub fn from_baz(baz: Baz) -> Result<Self, Error> {
        ...
    }
}
```

Note usage of third person instead of imperative.

Good: `/// Calculates the distance to the moon.`
Bad: `/// Calculate the distance to the moon.`

Add Panics section if any input to the function can trigger a panic.

Generally we prefer to have non-panicking APIs but it is impractical in some cases. If you're not
sure, feel free to ask. If we determine panicking is more practical it must be documented. Internal
panics that could theoretically occur because of bugs in our code must not be documented.

Example code within the rustdocs should compile and lint with `just lint` without any errors or
warnings.

### Links

We favour links at the bottom of the docs section:

```rust
    /// it is a real Taproot script spend (and not some other kind of output contrived
    /// to have a Taproot-shaped witness). See [BIP-0341] in particular footnote 7, for
    /// more information.
    ///
    /// [BIP-0341]: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
```

## Derives

We try to use standard set of derives if it makes sense:

```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Foo {
    Bar,
    Baz,
}
```

For types that do should not form a total or partial order, or that technically do but it does not
make sense to compare them, we use the `Ordered` trait from the
[`ordered`](https://crates.io/crates/ordered) crate. See `absolute::LockTime` for an example.

For error types you likely want to use `#[derive(Debug, Clone, PartialEq, Eq)]`.

See [Errors](#errors) section.


## Attributes

- `#[track_caller]`: Used on functions that panic on invalid arguments
  (see https://rustc-dev-guide.rust-lang.org/backend/implicit-caller-location.html)

- `#[cfg(rust_v_1_60)]`: Used to guard code that should only be built in if the toolchain is
  compatible. These configuration conditionals are set at build time in `bitcoin/build.rs`. New
  version attributes may be added as needed.


## BIP References

When referring to Bitcoin Improvement Proposals (BIPs) in documentation, comments, and error messages, use the standardized notation `BIP-XXXX` where `XXXX` is the 4-digit BIP number with leading zeros.

### Examples

- Correct: `BIP-0032`, `BIP-0341`, `BIP-0014`
- Incorrect: `BIP32`, `BIP 341`, `Bip14`, `bip_341`

### Exceptions

Module names, function names, variable names, and file names must keep their existing lowercase/underscore format. Do not rename them to match the formal BIP style:
- Module names: `bip32`, `bip152` (keep lowercase)
- Function names: `bip32_derivation`, `bip_341_tests` (keep existing format)

## Licensing

We use SPDX license tags, all files should start with

```
// SPDX-License-Identifier: CC0-1.0
```
