# 0.33.0-alpha - TODO: Set date

- Enforce script size limit when hashing scripts [#2794](https://github.com/rust-bitcoin/rust-bitcoin/pull/2794)

## Upgrade notes

- `MAX_SCRIPT_ELEMENT_SIZE` was removed in [#2794](https://github.com/rust-bitcoin/rust-bitcoin/pull/2794)
  you may want to use `MAX_REDEEM_SCRIPT_SIZE` or perhaps `MAX_STACK_ELEMENT_SIZE` (see `bitcoin/src/blockdata/constants`).
- `ecdsa::Error` was replaced by `ecdsa::DecodeError` and `ecdsa::ParseSignatureError`
  (returned by `ecdsa::Signature::from_slice` and `from_str` respectively).
- `script::read_scriptint` was move to be a method on `PushBytes`.
- You can likely just remove the `hashes::Hash` trait import.
- Change `OutPoint::default()` to `OutPoint::COINBASE_PREVOUT` if appropriate.
- Change `TxIn::default()` to `TxIn::EMPTY_COINBASE` if appropriate.
- Change `to_raw_hash()` to `to_byte_array()`.
- `bitcoin::error::UnprefixedHexError` moved to `bitcoin::parse::UnprefixedHexError`.

# 0.32.3 - 2024-09-27

- Backport BIP-32 alias' without typo [#3252](https://github.com/rust-bitcoin/rust-bitcoin/pull/3252)

# 0.32.2 - 2024-06-07

- Fix a bug when parsing 256-bit numeric types [#2837](https://github.com/rust-bitcoin/rust-bitcoin/pull/2837)

# 0.32.1 - 2024-05-29

Fix things we broke/removed from the `Address` API in the last release.

- Enable getting the witness program from an address [#2804](https://github.com/rust-bitcoin/rust-bitcoin/pull/2804)
- Make `Address:p2sh_from_hash` public [#2806](https://github.com/rust-bitcoin/rust-bitcoin/pull/2806)
- Add an `AddressData` type [#2810](https://github.com/rust-bitcoin/rust-bitcoin/pull/2810)

If you are looking for the `address::Payload` type we removed in `v0.32.0` then the `AddressData` type
might be what you are after.

# 0.32.0 - 2024-04-23

- Bump MSRV to Rust 1.56.1 [#2188](https://github.com/rust-bitcoin/rust-bitcoin/pull/2188)
- Remove "no-std" feature [#2233](https://github.com/rust-bitcoin/rust-bitcoin/pull/2233)
- Enforce displaying `Amount` with trailing zeros [#2604](https://github.com/rust-bitcoin/rust-bitcoin/pull/2604)

## Things you will almost certainly hit when upgrading

- Rename `Signature` field names [#2338](https://github.com/rust-bitcoin/rust-bitcoin/pull/2338)
  - `sig` becomes `signature`
  - `hash_ty` becomes `sighash_type`
- Rename `txid` to `compute_txid` [#2366](https://github.com/rust-bitcoin/rust-bitcoin/pull/2366)
- In hardcoded BIP-32 derivation paths: Remove `m/` prefix requirement [#2451](https://github.com/rust-bitcoin/rust-bitcoin/pull/2451)

## Crate smashing

This release we continued our effort to split up the library into
smaller crates AKA crate smashing.

- Release new `bitcoin-units` crate [docs](https://docs.rs/bitcoin-units/0.1.1/bitcoin_units/)
- Release new `base58ck` crate [docs](https://docs.rs/base58ck/0.1.0/base58ck/)
- Release new `bitcoin-io` crate [docs](https://docs.rs/bitcoin-io/0.1.2/bitcoin_io/)

## Bug fixes

- Fix `FeeRate::checked_mul_by_weight` [#2182](https://github.com/rust-bitcoin/rust-bitcoin/pull/2182)
- Use network when calculating difficulty [#2168](https://github.com/rust-bitcoin/rust-bitcoin/pull/2168)
- Fix `InputWeightPrediction::P2WPKH_MAX` constant DER sig length [#2213](https://github.com/rust-bitcoin/rust-bitcoin/pull/2213)
- Fix CJDNS marker byte check [#2546](https://github.com/rust-bitcoin/rust-bitcoin/pull/2546)
- Add resource limit check during deserialization of Merkle block [#2607](https://github.com/rust-bitcoin/rust-bitcoin/pull/2607)

## Changes to and involving the `Network` type

In release 0.31.0 we managed to annoy a lot of people by the addition of `non_exhaustive` to the
`Network` type. After much discussion, and in an effort to cater to multiple camps, we did a bunch
of changes this release. To sum up, "network" is ill defined and it means different things to
different devs/software. Your software should probably have some custom handling of whatever
"network" means to you.

In particular consider having some type that implements `AsRef<Params>`, we have attempted to
 replace `Network` in much of the API ([#2541](https://github.com/rust-bitcoin/rust-bitcoin/pull/2541)).

- Add `NetworkKind` [#2232](https://github.com/rust-bitcoin/rust-bitcoin/pull/2232)
- Reduce usage of `Network` in the public API [#2541](https://github.com/rust-bitcoin/rust-bitcoin/pull/2541)
- Remove `Network` from `AddressInner` [#1832](https://github.com/rust-bitcoin/rust-bitcoin/pull/1832)
- Add consts to `Params` for individual networks [#2396](https://github.com/rust-bitcoin/rust-bitcoin/pull/2396)
- Add `params()` method to `Network` [#2172](https://github.com/rust-bitcoin/rust-bitcoin/pull/2172)
- Use `KnowHrp`` instead of `Network` [#2387](https://github.com/rust-bitcoin/rust-bitcoin/pull/2387)
- Add check to max difficulty transition threshold [#2337](https://github.com/rust-bitcoin/rust-bitcoin/pull/2337)

## Other API additions

- Add `CompressedPublicKey` [#2277](https://github.com/rust-bitcoin/rust-bitcoin/pull/2277)
- Add a `consensus::deserialize_hex` function [#2039](https://github.com/rust-bitcoin/rust-bitcoin/pull/2039)
- Add `Witness::p2tr_key_spend` function [#2097](https://github.com/rust-bitcoin/rust-bitcoin/pull/2097)
- Add `taproot::SerializedSignature` [#2156](https://github.com/rust-bitcoin/rust-bitcoin/pull/2156)
- Add input weight predictions for p2pkh outputs [#2185](https://github.com/rust-bitcoin/rust-bitcoin/pull/2185)
- Add `Weight::from_vb_weight function` function (added in [#2206](https://github.com/rust-bitcoin/rust-bitcoin/pull/2206),
  renamed in [#2228](https://github.com/rust-bitcoin/rust-bitcoin/pull/2228)
- Implement `LowerHex` and `UpperHex` for `CompactTarget` [#2221](https://github.com/rust-bitcoin/rust-bitcoin/pull/2221)
- Add conversions from TXIDs to Merkle nodes [#2227](https://github.com/rust-bitcoin/rust-bitcoin/pull/2227)
- Add `transaction::effective_value()` function [#2230](https://github.com/rust-bitcoin/rust-bitcoin/pull/2230)
- Improve `LockTime`s and related types:
   - Improve relative locktime API [#2549](https://github.com/rust-bitcoin/rust-bitcoin/pull/2549)
   - Implement `ordered::ArbitraryOrd` for absolute and relative locktimes, introducing the "ordered" feature:
     - [#2581](https://github.com/rust-bitcoin/rust-bitcoin/pull/2581)
     - [#2248](https://github.com/rust-bitcoin/rust-bitcoin/pull/2248)
- Add and use custom `ArrayVec`
   - [#2287](https://github.com/rust-bitcoin/rust-bitcoin/pull/2287)
   - [#2286](https://github.com/rust-bitcoin/rust-bitcoin/pull/2286)
   - [#2310](https://github.com/rust-bitcoin/rust-bitcoin/pull/2310)
- Add the implementation of `Display` for `transaction::Version` [#2309](https://github.com/rust-bitcoin/rust-bitcoin/pull/2309)
- Add functionality to serialize signatures to a writer [#2392](https://github.com/rust-bitcoin/rust-bitcoin/pull/2392)
- Add unchecked integer operations to `Amount` and `SignedAmount` (add, sum etc.) [#2436](https://github.com/rust-bitcoin/rust-bitcoin/pull/2436)
- Add methods `p2wpkh_script_code` to `Script` and `ScriptBuf` [#2445](https://github.com/rust-bitcoin/rust-bitcoin/pull/2445)
- Improve API for signing Taproot inputs in PSBTs [#2458](https://github.com/rust-bitcoin/rust-bitcoin/pull/2458)
- Add `TapNodeHash` getter method on `TapTree` and `NodeInfo` [#2467](https://github.com/rust-bitcoin/rust-bitcoin/pull/2467)
- Add hex parsing to pow types [#2514](https://github.com/rust-bitcoin/rust-bitcoin/pull/2514)
- Implement `From<core::convert::Infallible>` for errors [#2516](https://github.com/rust-bitcoin/rust-bitcoin/pull/2516)
- Add ServiceFlags::P2P_V2 [#2555](https://github.com/rust-bitcoin/rust-bitcoin/pull/2555)

## Other API breaking changes

- Require `io::BufRead` instead of `io::Read` in consensus decode trait [#2240](https://github.com/rust-bitcoin/rust-bitcoin/pull/2240)
- Make `Payload` and `AddressEncoding` private [#1979](https://github.com/rust-bitcoin/rust-bitcoin/pull/1979)
- Remove `bech32` from the public API [#2381](https://github.com/rust-bitcoin/rust-bitcoin/pull/2381)
- Make from_hex inherent for byte-like types [#2491](https://github.com/rust-bitcoin/rust-bitcoin/pull/2491)
- Remove the FromHexStr trait [#2492](https://github.com/rust-bitcoin/rust-bitcoin/pull/2492)

## Error handling

- Split `Prevouts` errors out into specific error types [#2042](https://github.com/rust-bitcoin/rust-bitcoin/pull/2042)
- Improve error handling in the `sighash` module [#2329](https://github.com/rust-bitcoin/rust-bitcoin/pull/2329)
- Improve lock time errors [#2417](https://github.com/rust-bitcoin/rust-bitcoin/pull/2417)
- Split relative locktime error up [#2433](https://github.com/rust-bitcoin/rust-bitcoin/pull/2433)
- Improve `amount` module errors [#2487](https://github.com/rust-bitcoin/rust-bitcoin/pull/2487)
- Add the `FromScriptError` for handling errors in address [#2497](https://github.com/rust-bitcoin/rust-bitcoin/pull/2497)
- Add `NetworkValidationError` [#2508](https://github.com/rust-bitcoin/rust-bitcoin/pull/2508) but don't return it [#2610](https://github.com/rust-bitcoin/rust-bitcoin/pull/2610)
- Improve leaf errors ("leaf" means not enum with nested error type) [#2530](https://github.com/rust-bitcoin/rust-bitcoin/pull/2530)

# 0.31.1 - 2024-01-09

- Fix bug in `FeeRate::checked_mul_by_weight` [#2128](https://github.com/rust-bitcoin/rust-bitcoin/pull/2182)
- Add BIP-32 types remove in 0.31 back in and mark as deprecated [#2258](https://github.com/rust-bitcoin/rust-bitcoin/pull/2258)

# 0.31.0 - 2023-10-18

- Bump MSRV to Rust 1.48.0 [#1729](https://github.com/rust-bitcoin/rust-bitcoin/pull/1729)
- Add new example code for signature verification [#1776](https://github.com/rust-bitcoin/rust-bitcoin/pull/1776)
- Manually implement `Debug` on `Witness` [#1913](https://github.com/rust-bitcoin/rust-bitcoin/pull/1913)
- Use new bech32 API [#1951](https://github.com/rust-bitcoin/rust-bitcoin/pull/1951) and [#2117](https://github.com/rust-bitcoin/rust-bitcoin/pull/2117)
- Upgrade to `secp256k1 v0.28.0` [#2098](https://github.com/rust-bitcoin/rust-bitcoin/pull/2098)
- Upgrade to `base64 v0.21.3` [#2032](https://github.com/rust-bitcoin/rust-bitcoin/pull/2032)

- API Improvements:
  - Add kilo weight unit conversion [#1735](https://github.com/rust-bitcoin/rust-bitcoin/pull/1735)
  - Add `ChainHash::from_genesis_block_hash`[#1753](https://github.com/rust-bitcoin/rust-bitcoin/pull/1753)
  - Add implementation of `PartialEq` trait for `Address<NetworkUnchecked>` [#1757](https://github.com/rust-bitcoin/rust-bitcoin/pull/1757)
  - Add unsafe address type conversions [#1765](https://github.com/rust-bitcoin/rust-bitcoin/pull/1765)
  - Add `Inventory::network_hash()` method [#515](https://github.com/rust-bitcoin/rust-bitcoin/pull/515)
  - Implement `serde::Serialize` for `Address` [#1785](https://github.com/rust-bitcoin/rust-bitcoin/pull/1785)
  - Expose valid (min, max) difficulty transition thresholds [#1820](https://github.com/rust-bitcoin/rust-bitcoin/pull/1820)
  - Add functionality to generate `PrivateKey` [#1837](https://github.com/rust-bitcoin/rust-bitcoin/pull/1837)
  - Allow parsing sub-sat denominations with decimal points [#1768](https://github.com/rust-bitcoin/rust-bitcoin/pull/1768)
  - Fix associated constants of `InputWeightPrediction` [#1835](https://github.com/rust-bitcoin/rust-bitcoin/pull/1835)
  - Add `FeeRate::checked_mul_by_weight` [#1864](https://github.com/rust-bitcoin/rust-bitcoin/pull/1864)
  - Use `Amount` type for the `TxOut` value field [#1811](https://github.com/rust-bitcoin/rust-bitcoin/pull/1811)
  - Add support for alloc-free parse errors [#1297](https://github.com/rust-bitcoin/rust-bitcoin/pull/1297)
  - Add `Amount::from_int_btc` [#1870](https://github.com/rust-bitcoin/rust-bitcoin/pull/1870)
  - Make `ckd_priv` function private and impl `AsRef` for `ChildNumber` [#1882](https://github.com/rust-bitcoin/rust-bitcoin/pull/1882)
  - Use `hex_lit::hex` in benches (also backported to v0.30.1) [#1941](https://github.com/rust-bitcoin/rust-bitcoin/pull/1941)
  - Add a verify function to `PublicKey` [#1911](https://github.com/rust-bitcoin/rust-bitcoin/pull/1911)
  - Add method `Script::count_sigops` [#1890](https://github.com/rust-bitcoin/rust-bitcoin/pull/1890)
  - Implement `From<PublicKey> for XOnlyPublicKey` [#1901](https://github.com/rust-bitcoin/rust-bitcoin/pull/1901)
  - Implement `From<secp256k1::PublicKey> for bitcoin::PublicKey` [#1949](https://github.com/rust-bitcoin/rust-bitcoin/pull/1949)
  - Add `DerivationPath::to_u32_vec` [#1946](https://github.com/rust-bitcoin/rust-bitcoin/pull/1946)
  - Use `Target` as type for `pow_limit` [#2107](https://github.com/rust-bitcoin/rust-bitcoin/pull/2107)
  - Add `Witness::p2wpkh` constructor [#2084](https://github.com/rust-bitcoin/rust-bitcoin/pull/2084)
  - Make `Instruction` be able to read the script number [#2081](https://github.com/rust-bitcoin/rust-bitcoin/pull/2081)
  - Add `Script::is_mulitsig` [#2078](https://github.com/rust-bitcoin/rust-bitcoin/pull/2078)
  - Count sigops for `Transaction` [#2073](https://github.com/rust-bitcoin/rust-bitcoin/pull/2073)
  - Add `Psbt` fee checks [#2064](https://github.com/rust-bitcoin/rust-bitcoin/pull/2064)
  - Add version bytes consts [#2020](https://github.com/rust-bitcoin/rust-bitcoin/pull/2020)
  - Add `transaction::Version` data type [#2006](https://github.com/rust-bitcoin/rust-bitcoin/pull/2006)

- Moves, Removes, and renames:
  - Move witness types to the script module [#1846](https://github.com/rust-bitcoin/rust-bitcoin/pull/1846)
  - Remove reexport of `psbt::Prevouts` [#1872](https://github.com/rust-bitcoin/rust-bitcoin/pull/1872)
  - Rename `Transaction::is_coin_base` to `is_coinbase` [#1796](https://github.com/rust-bitcoin/rust-bitcoin/pull/1796)
  - Rename `TaprootSpendInfo::as_script_map` to `script_map` [#1897](https://github.com/rust-bitcoin/rust-bitcoin/pull/1897)
  - Rename `Script::empty` to `Script::new` [#1925](https://github.com/rust-bitcoin/rust-bitcoin/pull/1925)
  - Rename `PartiallySignedTransaction` to `Psbt` [#1938](https://github.com/rust-bitcoin/rust-bitcoin/pull/1938)
  - Rename `XpubIdenifier` to `XKeyIdentifier` [#2021](https://github.com/rust-bitcoin/rust-bitcoin/pull/2021)
  - Rename `ExtendedPubKey` to `Xpub` [#2019](https://github.com/rust-bitcoin/rust-bitcoin/pull/2019)
  - Rename `ExtendedPrivKey` to `Xpriv` [#2019](https://github.com/rust-bitcoin/rust-bitcoin/pull/2019)
  - Remove `_v0` from various function names (eg, `new_v0_p2wpkh`) [#1994](https://github.com/rust-bitcoin/rust-bitcoin/pull/1994)
  - Remove `SighashCache::segwit_signature_hash` (add `p2wpkh_signiture_hash` and `p2wsh_signature_hash`) [#1995](https://github.com/rust-bitcoin/rust-bitcoin/pull/1995)
  - Reexport all the hash types from the crate root [#1998](https://github.com/rust-bitcoin/rust-bitcoin/pull/1998)
  - Rename `opcodes::All` to `Opcode` [#1995](https://github.com/rust-bitcoin/rust-bitcoin/pull/1995)
  - Removed `TxOut::default()`, the same logic now exists as `TxOut::NULL` [#1811](https://github.com/rust-bitcoin/rust-bitcoin/pull/1811) and [#1838](https://github.com/rust-bitcoin/rust-bitcoin/pull/1838)

- Error handling improvements:
  - Improve `hashes::Error` [#1873](https://github.com/rust-bitcoin/rust-bitcoin/pull/1873)
  - Add `ValidationError` [#1874](https://github.com/rust-bitcoin/rust-bitcoin/pull/1874)
  - Improve `crypto::taproot` error type [#1895](https://github.com/rust-bitcoin/rust-bitcoin/pull/1895)
  - Audit error types code base wide [#2101](https://github.com/rust-bitcoin/rust-bitcoin/pull/2101)

# 0.30.2 - 2023-11-16

- Expose valid (min, max) difficulty transition thresholds [#1820](Expose valid (min, max) difficulty transition thresholds)

# 0.30.1 - 2023-07-16

- Fix compilation when [`RUSTFLAGS=--cfg=bench` is set](https://github.com/rust-bitcoin/rust-bitcoin/pull/1943)

# 0.30 - 2023-03-21 "The First Crate-Smashing Release"

We now have a website for crates that live under the `rust-bitcoin` GitHub organization: https://rust-bitcoin.org/

This release is big, to help users upgrade we wrote a blog post, please see https://rust-bitcoin.org/blog/release-0.30.0/

- [Import `bitcoin_hashes`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1284) into this repository.

- Update dependencies we control
  - Depend on the new private crate `bitcoin-private`
  - Depend on the new `bitcoin_hashes` v0.12
  - Depend on the new `secp256k1` v0.27

- We moved a lot of modules around, specifically we move basically everything out of `util`.

- API improvements:
  - [Use marker type to enforce validation of `Address`'s network](https://github.com/rust-bitcoin/rust-bitcoin/pull/1489)
  - [New `Witness` features](https://github.com/rust-bitcoin/rust-bitcoin/pull/1323)
  - [`Witness` API improvements](https://github.com/rust-bitcoin/rust-bitcoin/pull/1380)
  - Renamed `Script` to `ScriptBuf` and [added a new unsized type](https://github.com/rust-bitcoin/rust-bitcoin/pull/1155) `Script`
  - [Add `tapscript_leaf_hash()` to `Script`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1485)
  - [Unify `TapLeafHash` and `TapBranchHash` into `TapNodeHash` while tree construction](https://github.com/rust-bitcoin/rust-bitcoin/pull/1479)
  - [Add `Script::builder` convenience function](https://github.com/rust-bitcoin/rust-bitcoin/pull/1312)
  - [Implement `PartiallySignedTransaction::fee`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1338)
  - [Implement `Script::p2pk_public_key(&self) -> Option<PublicKey>`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1412)
  - [Add `log2` to `Work`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1437)
  - [Add weight utilities to `TxIn` and `TxOut`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1467)
  - [Add conversions for `TweakedKeyPair` -> `TweakedPublicKey`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1583)
  - [Add `From<Address>` for `ScriptBuf`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1592)
  - [Rename `from_slice` methods to `decode`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1621)
  - [Add methods for pushing locktimes to scripts](https://github.com/rust-bitcoin/rust-bitcoin/pull/1629)
  - [Create Address::matches_script_pubkey method](https://github.com/rust-bitcoin/rust-bitcoin/pull/1663)
  - [Add API method `absolute::LockTime::is_satisfied_by_lock`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1258)
  - [Add `FromHexStr`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1400) for parsing strings with and without `0x` prefix
  - [Add CentiBitcoin to denominations](https://github.com/rust-bitcoin/rust-bitcoin/pull/1715)
  - [Add `difficulty_float` method for `block::Header`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1720)

- Various sighash code moves, and type improvements:
  - [Improve `SighashCache` API](https://github.com/rust-bitcoin/rust-bitcoin/pull/1625)
  - [Do not export unusual hash types at crate root](https://github.com/rust-bitcoin/rust-bitcoin/pull/1617)
  - [Move sighash types around](https://github.com/rust-bitcoin/rust-bitcoin/pull/1597)
  - [Try to fix up sighash export mess](https://github.com/rust-bitcoin/rust-bitcoin/pull/1277)

- New types:
  - `ScriptBuf` ([Implement unsized `Script`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1155).
  - [Network `Magic`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1288)
  - [Add `Weight` and `FeeRate` newtypes](https://github.com/rust-bitcoin/rust-bitcoin/pull/1627)
  - [Add `Target` and `Work` types](https://github.com/rust-bitcoin/rust-bitcoin/pull/1197)
  - [Add `relative::LockTime` type](https://github.com/rust-bitcoin/rust-bitcoin/pull/1196)

- Removed types/traits:
  - [Remove `ToHex`](https://github.com/rust-bitcoin/rust-bitcoin/pull/1531)
  - [Remove code deprecated in v0.28](https://github.com/rust-bitcoin/rust-bitcoin/pull/1276)
  - Remove `PackedLockTime`, [replace with richer `LockTime` everywhere](https://github.com/rust-bitcoin/rust-bitcoin/pull/1330)
     Be aware that `LockTime` does not have an `Ord` implementation, so users who need a
     total ordering on locktimes will be forced to wrap this type. In `Transaction`, which
     contains a `LockTime` but is `Ord`, we have manually sorted the locktimes based on
     their consensus encoding. This ordering is somewhat arbitrary -- there is no total
     ordering on locktimes since they may be measured in either blocks or seconds.
  - [Removed `FromHex` implementation](https://github.com/rust-bitcoin/rust-bitcoin/pull/1565) from
    all types except `Vec` and arrays, replace where appropriate with `FromStr`.

- Performance improvements:
  - [Remove needless allocation from BIP-158 encoding](https://github.com/rust-bitcoin/rust-bitcoin/pull/1146)
  - [Implement fast hex encoding](https://github.com/rust-bitcoin/rust-bitcoin/pull/1268) (usage added in a [later PR](https://github.com/rust-bitcoin/rust-bitcoin/pull/1476))

- Testing improvements:
  - Started using [kani](https://github.com/model-checking/kani)
  - Started using [mutagen](https://github.com/llogiq/mutagen)

# 0.29 - 2022-07-20 "Edition 2018 Release"

As promised, this is our quick release to bring on edition 2018 by increasing our MSRV to Rust
1.41.1 [#983](https://github.com/rust-bitcoin/rust-bitcoin/pull/983)

This work saw a bunch of new language features become available to us. At the
same time we were able to start using `rustfmt`. We also started linting as part
of CI.

## Breaking changes

There are numerous breaking changes in this release related to the new language features but also
other improvements such as more newtypes added. Note that not all changes cause compilation failure!
For example, [`Witness` serialization was changed](https://github.com/rust-bitcoin/rust-bitcoin/pull/1068)
to support human-readable formats.

[Detailed list of breaking changes](https://github.com/rust-bitcoin/rust-bitcoin/pulls?q=is%3Apr+label%3A%22API+break%22+is%3Aclosed+milestone%3A0.29.0+)

## Highlights

- Added support for BIP 152 [#1088](https://github.com/rust-bitcoin/rust-bitcoin/pull/1088)
- Edition 2018 improvements
  - Implement `TryFrom` [#1007](https://github.com/rust-bitcoin/rust-bitcoin/pull/1007)
  - Add `non_exhaustive` to all error enums [#1026](https://github.com/rust-bitcoin/rust-bitcoin/pull/1026)
  - Various other improvements, see [tracking issue](https://github.com/rust-bitcoin/rust-bitcoin/issues/510) for more information.
- Enable `clippy` on CI [#1061](https://github.com/rust-bitcoin/rust-bitcoin/pull/1061)
- Taproot improvements
  [#950](https://github.com/rust-bitcoin/rust-bitcoin/pull/950) [#936](https://github.com/rust-bitcoin/rust-bitcoin/pull/936)
- serde improvements/changes
  [#1006](https://github.com/rust-bitcoin/rust-bitcoin/pull/1006) [#905](https://github.com/rust-bitcoin/rust-bitcoin/pull/905)
  [#1071](https://github.com/rust-bitcoin/rust-bitcoin/pull/1071) []
- Performance improvements
  [#1033](https://github.com/rust-bitcoin/rust-bitcoin/pull/1033) [#996](https://github.com/rust-bitcoin/rust-bitcoin/pull/996)
  [#1053](https://github.com/rust-bitcoin/rust-bitcoin/pull/1053) [#1023](https://github.com/rust-bitcoin/rust-bitcoin/pull/1023)
- PSBT improvements
  [#853](https://github.com/rust-bitcoin/rust-bitcoin/pull/853) [#951] (https://github.com/rust-bitcoin/rust-bitcoin/pull/951)
  [#940](https://github.com/rust-bitcoin/rust-bitcoin/pull/940)
- Script improvements
  [#1021](https://github.com/rust-bitcoin/rust-bitcoin/pull/1021) [#954](https://github.com/rust-bitcoin/rust-bitcoin/pull/954)
- New types that may be of interest
  - `Sequence`, transaction sequence number [#1093](https://github.com/rust-bitcoin/rust-bitcoin/pull/1093)
  - `ChainHash`, as used in Lightning [#878](https://github.com/rust-bitcoin/rust-bitcoin/pull/878)
  - `LockTime`, transaction nLockTime [#994](https://github.com/rust-bitcoin/rust-bitcoin/pull/994)
- Improve pubkey sorting: [#1084](https://github.com/rust-bitcoin/rust-bitcoin/pull/1084)
- Introduce `rustfmt` [#1040](https://github.com/rust-bitcoin/rust-bitcoin/pull/1040)
- Dependencies
  - Upgrade to use `bitcoinconsensus` v0.20.2-0.5.0 [#1165](https://github.com/rust-bitcoin/rust-bitcoin/pull/1165)
  - Upgrade to use `secp256k1` v0.24.0 [#1110](https://github.com/rust-bitcoin/rust-bitcoin/pull/1110)
  - Upgrade to use `bech32` v0.9.0 [#1131](https://github.com/rust-bitcoin/rust-bitcoin/pull/1131)
  - Remove `base64-compat` in favour of `base64` [#993](https://github.com/rust-bitcoin/rust-bitcoin/pull/993)
  - Do not pin transitive `ryu` dependency [#1013](https://github.com/rust-bitcoin/rust-bitcoin/pull/1013)
- Take `Writer`/`Reader` by `&mut` in consensus en/decoding [#1035](https://github.com/rust-bitcoin/rust-bitcoin/pull/1035)
- Consume `self` in conversion methods named `to_*` instead of borrowing [#1161](https://github.com/rust-bitcoin/rust-bitcoin/pull/1161)

# 0.28.2 - 2022-11-01

Backported a set of changes from 0.29 which may cause some specific
transactions and/or blocks to fail to deserialize. No known such transactions
exist on any public blockchain.

# 0.28 - 2022-04-20 "The Taproot Release"

At nearly nine months, this is our longest release cycle ever, and thanks
to a huge increase in the number of active contributors this year and last,
it is also **by far** our largest release ever, at 148 PRs merged from 23
different contributors. Our primary goal in this release was to introduce
support for Taproot and its associated data structures: addresses, taptrees,
sighashes, PSBT fields, and more. As it turned out, these changes required
(or at least, incentivized) changing a lot of our APIs, causing a significant
increase in scope.

We have more big changes coming down the pike. 2022 is going to be a big
year for `rust-bitcoin`, which we know is exciting for us but disruptive to
downstream users who ultimately want the library to just work. Our hope is
that by 2023 we will have eliminated large amounts of technical debt,
modernized our APIs to meet current Rust conventions, and clarified the scope
of the individual crates in this ecosystem while still providing the essential
functionality needed by our downstream users, especially wallet projects.

We will also develop a plan to make our releases more predictable and manageable,
likely by having scheduled releases with limited scope. We would like to reach
a point where we no longer have frequent breaking releases, but right now we
are nowhere close.

Upcoming changes will include
- A quick new release which updates our MRSV from 1.29 to 1.41 and does little else
- Updating our codebase to take advantage of the new MSRV, especially regarding
nostd and wasm support
- A comprehensive rethinking and flattening of our public-facing APIs
- Richer support for PSBT, Script, and BIP-0340/Schnorr signatures

With so many changes since 0.27, we cannot list every PR. Here are the highlights:

- Remove dangerous `fuzztarget` cargo feature [#634](https://github.com/rust-bitcoin/rust-bitcoin/pull/634)
- Improve serde serialization for `Script` [#596](https://github.com/rust-bitcoin/rust-bitcoin/pull/596)
- Documentation improvements [#623](https://github.com/rust-bitcoin/rust-bitcoin/pull/623) [#633](https://github.com/rust-bitcoin/rust-bitcoin/pull/633) [#663](https://github.com/rust-bitcoin/rust-bitcoin/pull/663) [#689](https://github.com/rust-bitcoin/rust-bitcoin/pull/689) [#704](https://github.com/rust-bitcoin/rust-bitcoin/pull/704) [#744](https://github.com/rust-bitcoin/rust-bitcoin/pull/744) [#852](https://github.com/rust-bitcoin/rust-bitcoin/pull/852) [#869](https://github.com/rust-bitcoin/rust-bitcoin/pull/869) [#865](https://github.com/rust-bitcoin/rust-bitcoin/pull/865) [#864](https://github.com/rust-bitcoin/rust-bitcoin/pull/864) [#858](https://github.com/rust-bitcoin/rust-bitcoin/pull/858) [#806](https://github.com/rust-bitcoin/rust-bitcoin/pull/806) [#877](https://github.com/rust-bitcoin/rust-bitcoin/pull/877) [#912](https://github.com/rust-bitcoin/rust-bitcoin/pull/912) [#923](https://github.com/rust-bitcoin/rust-bitcoin/pull/923)
- Introduce `WitnessVersion` type [#617](https://github.com/rust-bitcoin/rust-bitcoin/pull/617)
- Improve error types and API [#625](https://github.com/rust-bitcoin/rust-bitcoin/pull/625)
- Implement `Block.get_strippedsize()` and `Transaction.get_vsize()` [#626](https://github.com/rust-bitcoin/rust-bitcoin/pull/626)
- Add Bloom filter network messages [#580](https://github.com/rust-bitcoin/rust-bitcoin/pull/580)
- **Taproot:** add signature hash support [#628](https://github.com/rust-bitcoin/rust-bitcoin/pull/628) [#702](https://github.com/rust-bitcoin/rust-bitcoin/pull/702) [#722](https://github.com/rust-bitcoin/rust-bitcoin/pull/722) [#835](https://github.com/rust-bitcoin/rust-bitcoin/pull/835) [#903](https://github.com/rust-bitcoin/rust-bitcoin/pull/903) [#796](https://github.com/rust-bitcoin/rust-bitcoin/pull/796)
- **Taproot:** add new Script opcodes [#644](https://github.com/rust-bitcoin/rust-bitcoin/pull/644) [#721](https://github.com/rust-bitcoin/rust-bitcoin/pull/721) [#868](https://github.com/rust-bitcoin/rust-bitcoin/pull/868) [#920](https://github.com/rust-bitcoin/rust-bitcoin/pull/920)
- **Taproot:** add bech32m support, addresses and new key types [#563](https://github.com/rust-bitcoin/rust-bitcoin/pull/563) [#691](https://github.com/rust-bitcoin/rust-bitcoin/pull/691) [#697](https://github.com/rust-bitcoin/rust-bitcoin/pull/697) [#728](https://github.com/rust-bitcoin/rust-bitcoin/pull/728) [#696](https://github.com/rust-bitcoin/rust-bitcoin/pull/696) [#757](https://github.com/rust-bitcoin/rust-bitcoin/pull/757)
- **Taproot:** add taptree data structures [#677](https://github.com/rust-bitcoin/rust-bitcoin/pull/677) [#703](https://github.com/rust-bitcoin/rust-bitcoin/pull/703) [#701](https://github.com/rust-bitcoin/rust-bitcoin/pull/701) [#718](https://github.com/rust-bitcoin/rust-bitcoin/pull/718) [#845](https://github.com/rust-bitcoin/rust-bitcoin/pull/845) [#901](https://github.com/rust-bitcoin/rust-bitcoin/pull/901) [#910](https://github.com/rust-bitcoin/rust-bitcoin/pull/910) [#909](https://github.com/rust-bitcoin/rust-bitcoin/pull/909) [#914](https://github.com/rust-bitcoin/rust-bitcoin/pull/914)
- no-std improvements [#637](https://github.com/rust-bitcoin/rust-bitcoin/pull/637)
- PSBT improvements, including Taproot [#654](https://github.com/rust-bitcoin/rust-bitcoin/pull/654) [#681](https://github.com/rust-bitcoin/rust-bitcoin/pull/681) [#669](https://github.com/rust-bitcoin/rust-bitcoin/pull/669) [#774](https://github.com/rust-bitcoin/rust-bitcoin/pull/774) [#779](https://github.com/rust-bitcoin/rust-bitcoin/pull/779) [#752](https://github.com/rust-bitcoin/rust-bitcoin/pull/752) [#776](https://github.com/rust-bitcoin/rust-bitcoin/pull/776) [#790](https://github.com/rust-bitcoin/rust-bitcoin/pull/790) [#836](https://github.com/rust-bitcoin/rust-bitcoin/pull/836) [#847](https://github.com/rust-bitcoin/rust-bitcoin/pull/847) [#842](https://github.com/rust-bitcoin/rust-bitcoin/pull/842)
- serde improvements [#672](https://github.com/rust-bitcoin/rust-bitcoin/pull/672)
- Update rust-secp256k1 dependency [#694](https://github.com/rust-bitcoin/rust-bitcoin/pull/694) [#755](https://github.com/rust-bitcoin/rust-bitcoin/pull/755) [#875](https://github.com/rust-bitcoin/rust-bitcoin/pull/875)
- Change BIP32 to use rust-secp256k1 keys rather than rust-bitcoin ones (no compressedness flag) [#590](https://github.com/rust-bitcoin/rust-bitcoin/pull/590) [#591](https://github.com/rust-bitcoin/rust-bitcoin/pull/591)
- Rename inner key field in `PrivateKey` and `PublicKey` [#762](https://github.com/rust-bitcoin/rust-bitcoin/pull/762)
- Address and denomination related changes [#768](https://github.com/rust-bitcoin/rust-bitcoin/pull/768) [#784](https://github.com/rust-bitcoin/rust-bitcoin/pull/784)
- Don't allow hybrid EC keys [#829](https://github.com/rust-bitcoin/rust-bitcoin/pull/829)
- Change erroneous behavior for `SIGHASH_SINGLE` bug [#860](https://github.com/rust-bitcoin/rust-bitcoin/pull/860) [#897](https://github.com/rust-bitcoin/rust-bitcoin/pull/897)
- Delete the deprecated `contracthash` module [#871](https://github.com/rust-bitcoin/rust-bitcoin/pull/871); this functionality will migrate to ElementsProject/rust-elements
- Remove compilation-breaking feature-gating of enum variants" [#881](https://github.com/rust-bitcoin/rust-bitcoin/pull/881)

Additionally we made several minor API changes (renaming methods, etc.) to improve
compliance with modern Rust conventions. Where possible we left the existing methods
in place, marked as deprecated.

# 0.27 - 2021-07-21

- [Bigendian fixes and CI test](https://github.com/rust-bitcoin/rust-bitcoin/pull/627)
- [no_std support, keeping MSRV](https://github.com/rust-bitcoin/rust-bitcoin/pull/603)
- [Bech32m adoption](https://github.com/rust-bitcoin/rust-bitcoin/pull/601)
- [Use Amount type for dust value calculation](https://github.com/rust-bitcoin/rust-bitcoin/pull/616)
- [Errors enum improvements](https://github.com/rust-bitcoin/rust-bitcoin/pull/521)
- [std -> core](https://github.com/rust-bitcoin/rust-bitcoin/pull/614)

# 0.26.2 - 2021-06-08

- [Fix `Display` impl of `ChildNumber`](https://github.com/rust-bitcoin/rust-bitcoin/pull/611)

The previous release changed the behavior of `Display` for `ChildNumber`, assuming that any correct usage would not be
affected. [Issue 608](https://github.com/rust-bitcoin/rust-bitcoin/issues/608) goes into the details of why this isn't
the case and how we broke both `rust-miniscript` and BDK.

# 0.26.1 - 2021-06-06 (yanked, see explanation above)

- [Change Amount Debug impl to BTC with 8 decimals](https://github.com/rust-bitcoin/rust-bitcoin/pull/414)
- [Make uint types (un)serializable](https://github.com/rust-bitcoin/rust-bitcoin/pull/511)
- Add [more derives for key::Error](https://github.com/rust-bitcoin/rust-bitcoin/pull/551)
- [Fix optional amount serialization](https://github.com/rust-bitcoin/rust-bitcoin/pull/552)
- Add [PSBT base64 (de)serialization with Display & FromStr](https://github.com/rust-bitcoin/rust-bitcoin/pull/557)
- Add [non-API breaking derives for error & transaction types](https://github.com/rust-bitcoin/rust-bitcoin/pull/558)
- [Fix error derives](https://github.com/rust-bitcoin/rust-bitcoin/pull/559)
- [Add function to check RBF-ness of transactions](https://github.com/rust-bitcoin/rust-bitcoin/pull/565)
- [Add Script:dust_value() to get minimum output value for a spk](https://github.com/rust-bitcoin/rust-bitcoin/pull/566)
- [Improving bip32 ChildNumber display implementation](https://github.com/rust-bitcoin/rust-bitcoin/pull/567)
- [Make Script::fmt_asm a static method and add Script::str_asm ](https://github.com/rust-bitcoin/rust-bitcoin/pull/569)
- [Return BlockHash from BlockHeader::validate_pow](https://github.com/rust-bitcoin/rust-bitcoin/pull/572)
- [Add a method to error on non-standard hashtypes](https://github.com/rust-bitcoin/rust-bitcoin/pull/573)
- [Include proprietary key in deserialized PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/577)
- [Fix Script::dust_value()'s calculation for non-P2*PKH script_pubkeys](https://github.com/rust-bitcoin/rust-bitcoin/pull/579)
- Add [Address to optimized QR string](https://github.com/rust-bitcoin/rust-bitcoin/pull/581) conversion
- [Correct Transaction struct encode_signing_data_to doc comment](https://github.com/rust-bitcoin/rust-bitcoin/pull/582)
- Fixing [CI if base image's apt db is outdated](https://github.com/rust-bitcoin/rust-bitcoin/pull/583)
- [Introduce some policy constants from Bitcoin Core](https://github.com/rust-bitcoin/rust-bitcoin/pull/584)
- [Fix warnings for sighashtype](https://github.com/rust-bitcoin/rust-bitcoin/pull/586)
- [Introduction of Schnorr keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/589)
- Adding [constructors for compressed and uncompressed ECDSA keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/592)
- [Count bytes read in encoding](https://github.com/rust-bitcoin/rust-bitcoin/pull/594)
- [Add verify_with_flags to Script and Transaction](https://github.com/rust-bitcoin/rust-bitcoin/pull/598)
- [Fixes documentation intra-links and enforce it](https://github.com/rust-bitcoin/rust-bitcoin/pull/600)
- [Fixing hashes core dependency and fuzz feature](https://github.com/rust-bitcoin/rust-bitcoin/pull/602)

# 0.26.0 - 2020-12-21

- Add [signet support](https://github.com/rust-bitcoin/rust-bitcoin/pull/291)
- Add [wtxidrelay message and `WTx` inv type](https://github.com/rust-bitcoin/rust-bitcoin/pull/446) for BIP 339
- Add [addrv2 support](https://github.com/rust-bitcoin/rust-bitcoin/pull/449)
- Distinguish [`FilterHeader` and `FilterHash`](https://github.com/rust-bitcoin/rust-bitcoin/pull/454)
- Add [hash preimage fields](https://github.com/rust-bitcoin/rust-bitcoin/pull/478) to PSBT
- Detect [write errors for `PublicKey::write_into`](https://github.com/rust-bitcoin/rust-bitcoin/pull/507)
- impl `Ord` and `PartialOrd` [for `Inventory`](https://github.com/rust-bitcoin/rust-bitcoin/pull/517)
- Add [binary encoding for BIP32 xkeys](https://github.com/rust-bitcoin/rust-bitcoin/pull/470)
- Add [Taproot Tagged Hashes](https://github.com/rust-bitcoin/rust-bitcoin/pull/259)
- Add [`message::MAX_INV_SIZE` constant](https://github.com/rust-bitcoin/rust-bitcoin/pull/516)
- impl [`ToSocketAddrs` for network addresses](https://github.com/rust-bitcoin/rust-bitcoin/pull/514)
- Add [new global fields to PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/499)
- [Serde serialization of PSBT data](https://github.com/rust-bitcoin/rust-bitcoin/pull/497)
- [Make `Inventory` and `NetworkMessage` enums exhaustive](https://github.com/rust-bitcoin/rust-bitcoin/pull/496)
- [Add PSBT proprietary keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/471)
- [Add `PublicKey::read_from` method symmetric with `write_to`](https://github.com/rust-bitcoin/rust-bitcoin/pull/542)
- [Bump rust-secp to 0.20, turn off `recovery` feature by default](https://github.com/rust-bitcoin/rust-bitcoin/pull/545)
- [Change return value of `consensus_encode` to `io::Error`](https://github.com/rust-bitcoin/rust-bitcoin/pull/494)

# 0.25.1 - 2020-10-26

- Remove an incorrect `debug_assert` that can cause a panic when running using
  the dev profile.

# 0.25.1 - 2020-10-07

- [Expose methods on `Script`](https://github.com/rust-bitcoin/rust-bitcoin/pull/387) to generate various scriptpubkeys
- [Expose all cargo features of secp256k1](https://github.com/rust-bitcoin/rust-bitcoin/pull/486)
- Allow directly creating [various hash newtypes](https://github.com/rust-bitcoin/rust-bitcoin/pull/388)
- Add methods to `Block` [to get the coinbase tx and BIP34 height commitment](https://github.com/rust-bitcoin/rust-bitcoin/pull/444)
- [Add `extend` method](https://github.com/rust-bitcoin/rust-bitcoin/pull/459) to bip32::DerivationPath
- [Alias `(Fingerprint, DerivationPath)` as `KeySource`](https://github.com/rust-bitcoin/rust-bitcoin/pull/480)
- [Add serde implementation for PSBT data structs](https://github.com/rust-bitcoin/rust-bitcoin/pull/497)
- [Add FromStr/Display implementation for SigHashType](https://github.com/rust-bitcoin/rust-bitcoin/pull/497/commits/a4a7035a947998c8d0d69dab206e97253fd8e048)
- Expose [the raw sighash message](https://github.com/rust-bitcoin/rust-bitcoin/pull/485) from sighash computations
- Add [support for signmessage/verifymessage style message signatures](https://github.com/rust-bitcoin/rust-bitcoin/pull/413)

# 0.25.0 - 2020-09-10

- **Bump MSRV to 1.29.0**

# 0.24.0 - 2020-09-10

- [Remove](https://github.com/rust-bitcoin/rust-bitcoin/pull/385) the `BitcoinHash` trait
- [Introduce `SigHashCache` structure](https://github.com/rust-bitcoin/rust-bitcoin/pull/390) to replace `SighashComponents` and support all sighash modes
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/416) `Transaction::get_size` method
- [Export](https://github.com/rust-bitcoin/rust-bitcoin/pull/412) `util::amount::Denomination`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/417) `Block::get_size` and `Block::get_weight` methods
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/415) `MerkleBlock::from_header_txids`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/429) `BlockHeader::u256_from_compact_target`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/448) `feefilter` network message
- [Cleanup/replace](https://github.com/rust-bitcoin/rust-bitcoin/pull/397) `Script::Instructions` iterator API
- [Disallow uncompressed pubkeys in witness address generation](https://github.com/rust-bitcoin/rust-bitcoin/pull/428)
- [Deprecate](https://github.com/rust-bitcoin/rust-bitcoin/pull/451) `util::contracthash` module
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/435) modulo division operation for `Uint128` and `Uint256`
- [Add](https://github.com/rust-bitcoin/rust-bitcoin/pull/436) `slice_to_u64_be` endian conversion method

# 0.23.0 - 2020-01-07

- Update `secp256k1` dependency to `0.17.1`.
- Update `bitcoinconsensus` dependency to `0.19.0-1`.
- Update `bech32` dependency to `0.7.2`.

# 0.22.0 - 2020-01-07

- Add `ServiceFlags` type.
- Add `NetworkMessage::command`.
- Add `key::Error`.
- Add newtypes for specific hashes:
    - `Txid`
    - `Wtxid`
    - `BlockHash`
    - `SigHash`
    - `PubkeyHash`
    - `ScriptHash`
    - `WPubkeyHash`
    - `WScriptHash`
    - `TxMerkleNode`
    - `WitnessMerkleNode`
    - `WitnessCommitment`
    - `XpubIdentifier`
    - `FilterHash`
- Refactor `CommandString`.
- Refactor `Reject` message.
- Rename `RejectReason` enum variants.
- Refactor `encode::Error`.
- Implement `Default` for `TxIn`.
- Implement `std::hash::Hash` for `Inventory`.
- Implement `Copy` for `InvType` enum.
- Use `psbt::Error` in `PartiallySignedTransaction::from_unsigned_tx`.
- Drop message decode max length to 4_000_000.
- Drop `hex` and `byteorder` dependencies.

# 0.21.0 - 2019-10-02

* Add [serde to `BlockHeader` and `Block`](https://github.com/rust-bitcoin/rust-bitcoin/pull/321)
* [Clean up `StreamReader` API](https://github.com/rust-bitcoin/rust-bitcoin/pull/318) (breaking change)
* Add [reject message](https://github.com/rust-bitcoin/rust-bitcoin/pull/323) to p2p messages

# 0.20.0 - 2019-08-23

* Update `secp256k1` 0.15 and `bitcoinconsensus` 0.17

# 0.19.0 - 2019-08-16

* Add `Amount` and `SignedAmount` types.
* Add BIP-158 support with `BlockFilter` and related types.
* Add `util::misc::signed_msg_hash()` for signing messages.
* Add `MerkleBlock` and `PartialMerkleTree` types.
* bip32: Support serde serializaton for types and add some utility methods:
    * `ChildNumber::increment`
    * `DerivationPath::children_from`
    * `DerivationPath::normal_children`
    * `DerivationPath::hardened_children`
* Add `blockdata::script::Builder::push_verify` to verify-ify an opcode.
* Add `sendheaders` network message.
* Add `OutPoint::new()` method and JSON-serialize as `<txid>:<vout>`.
* Refactor `Address` type:
    * Now supports segwit addresses with version >0.
    * Add `Address::from_script` constructor.
    * Add `Address::address_type` inspector.
    * Parsing now returns an `address::Error` instead of `encode::Error`.
    * Removed `bitcoin_bech32` dependency for bech32 payloads.
* bip143: Rename `witness_script` to `script_code`
* Rename `BlockHeader::spv_validate` to `validate_pow`
* Rename `OP_NOP2` and `OP_NOP3` to `OP_CLTV` and `OP_CSV`
* psbt: Use `BTreeMap` instead of `HashMap` to ensure serialization roundtrips.
* Drop `Decimal` type.
* Drop `LoneHeaders` type.
* Replace `strason` dependency with (optional) `serde_json`.
* Export the `bitcoin_hashes` and `secp256k1` dependent crates.
* Updated `bitcoin_hashes` dependency to v0.7.
* Removed `rand` and `serde_test` dependencies.
* Internal improvements to consensus encoding logic.

# 0.18.0 - 2019-03-21

* Update `bitcoin-bech32` version to 0.9
* add `to_bytes` method for `util::key` types
* add serde impls for `util::key` types
* contracthash: minor cleanups, use `util::key` types instead of `secp256k1` types

# 0.17.1 - 2019-03-04

* Add some trait impls to `PublicKey` for miniscript interoperability

# 0.17.0 - 2019-02-28 - ``The PSBT Release''

* **Update minimum rustc version to 1.22**.
* [Replace `rust-crypto` with `bitcoin_hashes`; refactor hash types](https://github.com/rust-bitcoin/rust-bitcoin/pull/215)
* [Remove `Address::p2pk`](https://github.com/rust-bitcoin/rust-bitcoin/pull/222/)
* Remove misleading blanket `MerkleRoot` implementation; [it is now only defined for `Block`](https://github.com/rust-bitcoin/rust-bitcoin/pull/218)
* [Add BIP157](https://github.com/rust-bitcoin/rust-bitcoin/pull/215) (client-side block filtering messages)
* Allow network messages [to be deserialized even across multiple packets](https://github.com/rust-bitcoin/rust-bitcoin/pull/231)
* [Replace all key types](https://github.com/rust-bitcoin/rust-bitcoin/pull/183) to better match abstractions needed for PSBT
* [Clean up BIP32](https://github.com/rust-bitcoin/rust-bitcoin/pull/233) in preparation for PSBT; [use new native key types rather than `secp256k1` ones](https://github.com/rust-bitcoin/rust-bitcoin/pull/238/)
* Remove [apparently-used `Option` serialization](https://github.com/rust-bitcoin/rust-bitcoin/pull/236#event-2158116421) code
* Finally merge [PSBT](https://github.com/rust-bitcoin/rust-bitcoin/pull/103) after nearly nine months

# 0.16.0 - 2019-01-15

* Reorganize opcode types to eliminate unsafe code
* Un-expose some macros that were unintentionally exported
* Update rust-secp256k1 dependency to 0.12
* Remove `util::iter::Pair` type which does not belong in this library
* Minor bugfixes and optimizations

# 0.15.1 - 2018-11-08

* [Detect p2pk addresses with compressed keys](https://github.com/rust-bitcoin/rust-bitcoin/pull/189)

# 0.15.0 - 2018-11-03

* [Significant API overhaul](https://github.com/rust-bitcoin/rust-bitcoin/pull/156):
    * Remove `nu_select` macro and low-level networking support
    * Move `network::consensus_params` to `consensus::params`
    * Move many other things into `consensus::params`
    * Move `BitcoinHash` from `network::serialize` to `util::hash`; remove impl for `Vec<u8>`
    * Rename/restructure error types
    * Rename `Consensus{De,En}coder` to `consensus::{De,En}coder`
    * Replace `Raw{De,En}coder` with blanket impls of `consensus::{De,En}coder` on `io::Read` and `io::Write`
    * make `serialize` and `serialize_hex` infallible
* Make 0-input transaction de/serialization [always use segwit](https://github.com/rust-bitcoin/rust-bitcoin/pull/153)
* Implement `FromStr` and `Display` for many more types

# 0.14.2 - 2018-09-11

* Add serde support for `Address`

# 0.14.1 - 2018-08-28

* Reject non-compact `VarInt`s on various types
* Expose many types at the top level of the crate
* Add `Ord`, `PartialOrd` impls for `Script`

# 0.14.0 - 2018-08-22

* Add [regtest network](https://github.com/rust-bitcoin/rust-bitcoin/pull/84) to `Network` enum
* Add [`Script::is_op_return()`](https://github.com/rust-bitcoin/rust-bitcoin/pull/101/) which is more specific than
  `Script::is_provably_unspendable()`
* Update to bech32 0.8.0; [add Regtest bech32 address support](https://github.com/rust-bitcoin/rust-bitcoin/pull/110)
* [Replace rustc-serialize dependency with hex](https://github.com/rust-bitcoin/rust-bitcoin/pull/107) as a stopgap
  toward eliminating any extra dependencies for this; clean up the many independent hex encoders and decoders
  throughout the codebase.
* [Add conversions between `ChildNumber` and `u32`](https://github.com/rust-bitcoin/rust-bitcoin/pull/126); make
  representation non-public; fix documentation
* [Add several derivation convenience](https://github.com/rust-bitcoin/rust-bitcoin/pull/129) to `bip32` extended keys
* Make `deserialize::deserialize()` [enforce no trailing bytes](https://github.com/rust-bitcoin/rust-bitcoin/pull/129)
* Replace `TxOutRef` with `OutPoint`; use it in `TxIn` struct.
* Use modern `as_` `to_` `into_` conventions for array-wrapping types; impl `Display` rather than `ToString` for most types
* Change `script::Instructions` iterator [to allow rejecting non-minimal pushes](https://github.com/rust-bitcoin/rust-bitcoin/pull/136);
  fix bug where errors would iterate forever.
* Overhaul `util::Error`; introduce `serialize::Error` [and use it for `SimpleDecoder` and `SimpleDecoder` rather
  than parameterizing these over their error type](https://github.com/rust-bitcoin/rust-bitcoin/pull/137).
* Overhaul `UDecimal` and `Decimal` serialization and parsing [and fix many lingering parsing bugs](https://github.com/rust-bitcoin/rust-bitcoin/pull/142)
* [Update to serde 1.0 and strason 0.4](https://github.com/rust-bitcoin/rust-bitcoin/pull/125)
* Update to secp256k1 0.11.0
* Many, many documentation and test improvements.

# 0.13.1

* Add `Display` trait to uints, `FromStr` trait to `Network` enum
* Add witness inv types to inv enum, constants for Bitcoin regtest network, `is_coin_base` accessor for tx inputs
* Expose `merkleroot(Vec<Sha256dHash>)`

# 0.13

* Move witnesses inside the `TxIn` structure
* Add `Transaction::get_weight()`
* Update bip143 `sighash_all` API to be more ergonomic

# 0.12

* The in-memory blockchain was moved into a dedicated project rust-bitcoin-chain.
* Removed old script interpreter
* A new optional feature "bitcoinconsensus" lets this library use Bitcoin Core's native
script verifier, wrappend into Rust by the rust-bitcoinconsenus project.
See `Transaction::verify` and `Script::verify` methods.
* Replaced Base58 traits with `encode_slice`, `check_encode_slice`, from and `from_check` functions in the base58 module.
* Un-reversed the Debug output for Sha256dHash
* Add bech32 support
* Support segwit address types

### 0.11

* Remove `num` dependency at Matt's request; agree this is obnoxious to require all
downstream users to also have a `num` dependency just so they can use `Uint256::from_u64`.
