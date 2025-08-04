# `rust-bitcoin` repository roadmap

* ~Release `units v1.0.0-rc.0`~
* Release `primitives v1.0.0-rc.0`
  * Implement script tagging
  * Add support for consensus encoding to `primitives`
* Release `bitcoin v0.33.0-rc.0`
* Split out an address crate (see [address.md])
* BIP-32 and BIP-380 (see [bip-32.md]
* PSBTv2 (see [psbt.md])

## RC cycle

We want to do a long release candidate cycle to give time for downstream testing and feedback on the
API of the 1.0 crates. At a minimum this will be 6 months from the release `primitives-1.0-rc.0`.

[address.md]: ./address.md
[bip-32.md]: ./bip-32.md
[psbt.md]: ./psbt.md
