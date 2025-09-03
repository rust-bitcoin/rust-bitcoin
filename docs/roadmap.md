# `rust-bitcoin` repository roadmap

* ~Release `units v1.0.0-rc.0`~
* Create `bitcoin-consensus-encoding` `v0.1.0` (see [#4782])
* Release `bitcoin-consensus-encoding` `v1.0.0-rc.0`
* Release `primitives v1.0.0-rc.0`
  * Implement script tagging
  * Add support for consensus encoding to `primitives`
* Release `bitcoin v0.33.0-rc.0`
* Split out an address crate (see [addresses.md])
* BIP-32 and BIP-380 (see [bip-32.md])
* PSBTv2 (see [psbt.md])
* Split out a crypto/keys crate. Includes discussion of `secp256k1`. See [crypto.md]
* Make it possible for `bitcoin` to depend on `miniscript` (see [#2882])
    - Requires [bip-32.md] and [psbt.md]
* Disentangle and stabilize Taproot stuff (see [taproot.md])

## RC cycle

We want to do a long release candidate cycle to give time for downstream testing and feedback on the
API of the 1.0 crates. At a minimum this will be 6 months from the release `primitives-1.0-rc.0`.

[addresses.md]: ./addresses.md
[bip-32.md]: ./bip-32.md
[crypto.md]: ./crypto.md
[psbt.md]: ./psbt.md
[taproot.md]: ./taproot.md
[#2882]: <https://github.com/rust-bitcoin/rust-bitcoin/issues/2882>
