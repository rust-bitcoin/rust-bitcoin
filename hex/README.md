# Bitcoin Hexadecimal Library

This is a hex library designed to be fast and have a conservative MSRV.

## Minimum Supported Rust Version (MSRV)

This library should compile with almost any combination of features on **Rust 1.48.0**, however we
reserve the right to use features to guard compiler specific code so `--all-features` may not work
using the MSRV toolchain.

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.
