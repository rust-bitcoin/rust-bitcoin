// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.
//!
//! *[See also the `Script` type](Script).*
//!
//! This module provides the structures and functions needed to support scripts.
//!
//! <details>
//! <summary>What is Bitcoin script</summary>
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid iff
//! the script leaves `TRUE` on the stack after being evaluated. Bitcoin's
//! script is a stack-based assembly language similar in spirit to [Forth].
//!
//! Script is represented as a sequence of bytes on the wire, each byte representing an operation,
//! or data to be pushed on the stack.
//!
//! See [Bitcoin Wiki: Script][wiki-script] for more information.
//!
//! [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
//!
//! [wiki-script]: https://en.bitcoin.it/wiki/Script
//! </details>
//!
//! In this library we chose to keep the byte representation in memory and decode opcodes only when
//! processing the script. This is similar to Rust choosing to represent strings as UTF-8-encoded
//! bytes rather than slice of `char`s. In both cases the individual items can have different sizes
//! and forcing them to be larger would waste memory and, in case of Bitcoin script, even some
//! performance (forcing allocations).
//!
//! ## `Script` vs `ScriptBuf` vs `Builder`
//!
//! These are the most important types in this module and they are quite similar, so it may seem
//! confusing what the differences are. `Script` is an unsized type much like `str` or `Path` are
//! and `ScriptBuf` is an owned counterpart to `Script` just like `String` is an owned counterpart
//! to `str`.
//!
//! However it is common to construct an owned script and then pass it around. For this case a
//! builder API is more convenient. To support this we provide `Builder` type which is very similar
//! to `ScriptBuf` but its methods take `self` instead of `&mut self` and return `Self`. It also
//! contains a cache that may make some modifications faster. This cache is usually not needed
//! outside of creating the script.
//!
//! At the time of writing there's only one operation using the cache - `push_verify`, so the cache
//! is minimal but we may extend it in the future if needed.

/// Re-export everything from the [`primitives::script`] module.
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::script::*;
