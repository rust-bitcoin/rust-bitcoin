# 0.1.1 - 2024-04-04

* Enable "alloc" feature for `internals` dependency - enables caching
  of parsed input strings in a couple of `amount` error types.

# 0.1.0 - Initial Release - 2024-04-03

Initial release of the `bitcoin-units` crate. These unit types are
integer wrapper types used by the `rust-bitcoin` ecosystem. Note
please that this release relies heavily on the "alloc" feature.

The main types are:

- `Amount`
- `locktime::absolute::{Height, Time}`
- `locktime::relative::{Height, Time}`
- `FeeRate`
- `Weight`

# 0.0.0 - Placeholder release

Empty crate to reserve the name on crates.io