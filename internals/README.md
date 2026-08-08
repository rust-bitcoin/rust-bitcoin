# Rust Bitcoin Internals

This crate is only meant to be used internally by crates in the
[rust-bitcoin](https://github.com/rust-bitcoin) ecosystem.

This crate will never be stabilized, depend on it at your own risk.

## Exported Macros

Unlike ordinary functions and types, breaking changes to macro-generated code are largely invisible
to tooling (e.g. `cargo-semver-checks` or rustdoc-based API diffing), so exported macros are held
to a stricter, more conservative set of rules.

- Only declarative macros (`macro_rules!`).
- No macro may contain a `cfg`-gate within it. If callers need to conditionally include
  generated items, they should pass the relevant attribute(s) in as macro input (e.g. via a
  `$(#[$($attr)*])*` token-capture) or split up a macro's implantation, rather than hardcoding
  specific feature/cfg name inside the macro body.
- No macro may refer to types from any pre-1.0 crate.
- Any change to the body of an exported macro **requires a major version bump of
  `bitcoin-internals`**, unless reviewers are convinced the change is behavior-preserving.
