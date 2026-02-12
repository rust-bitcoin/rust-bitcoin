# rust-bitcoin documentation

This directory holds documentation for the `rust-bitcoin` repository and potentially various other
directly related crates from the `rust-bitcoin` GitHub organization (e.g. `rust-secp256k1`).

In general, PR discussions on source code should be about the technical content of changes. To debate
whether a change should be made at all, or the strategy for making changes, it is better to first PR to
the `docs/` tree. If a PR discussion veers into this sort of strategic discussion, the PR should be put on
hold and a PR made to the `docs/` tree or in the Discussions section to debate it before moving forward.

## Dependency tree

The `./dep-tree` file was generated using `just gen-dep-tree`.

## include! usage

In this repository, the `include` directory holds shared source code that can be used in any of the
crates through the `include!` macro. Generally, files in the `include` directory should be written
such that their content can be included once at the top level of a crate (e.g. in `lib.rs`), and
then used throughout, rather than calling `include!` at each usage site.