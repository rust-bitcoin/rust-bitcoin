Continuous Integration: rust-bitcoin test runner
================================================

This is a Rust program used in our CI pipeline (by way of GitHub actions) to test the `rust-bitcoin`
library. It can, of course, also be used from the command line to check your PRs before pushing (you
totally do that, right?)

For command execution, uses the [rust_cmd_lib](https://github.com/rust-shell-script/rust_cmd_lib)
crate.
