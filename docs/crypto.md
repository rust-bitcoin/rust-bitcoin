# Bitcoin keys / Bitcoin crypto

Either `bitcoin-keys` and just have keys in it or `bitcoin-crypto` and
have the other stuff from `bitcoin::crypto` in it.

## `secp256k1`

Both `bitcoin-keys` and `bitcoin-crypto` would depend on `secp256k1`.

Other things that use secp directly or indirectly through keys/crypto:

- `addresses` (for keys only)
- `bip-32` (for keys only)
- `psbt` for keys and signing
- Taproot script extension methods
- `bitcoin::taproot` module (uses secp directly)
- `bitcoin::sign_message` module (uses secp directly)

Taproot stuff is quite entangled in various places throughout the
codebase which in turn entangles secp.

## Keys

Public and private keys. 

The reason for splitting this out is so that other crates can depend on keys without depending on
`bitcoin` e.g., `addresses`.

(Note plural for crate name and singular for current module name, in line with what we did for
`address` module and `addresses` crate.)

Current public types in `bitcoin::crypto::key`:

- `XOnlyPublicKey`
- `PublicKey`
- `SortKey`
- `PubkeyHash`
- `WPubkeyHash`
- `CompressedPublicKey`
- `PrivateKey`
- `TweakedPublicKey`
- `TweakedKeypair`
- `SerializedXOnlyPublicKey`
- Various error types
- `TapTweak` trait

### Current obvious complications

Looking at `bitcoin::crypto::key` there are some obvious things that will need fixing.

#### `NetworkKind`

Currently we are using `bitcoin::network::NetworkKind` in `PrivateKey`.

- Used to get the first byte of WIF format
- Passed to functions that create addresses e.g., `Address::p2pkh(key, network)`

#### `ScriptBuf`

Possibly ok if we have a dependency on `primitives`. Only used for sciptcode.

#### Taproot stuff

`TapNodeHash` and `TapTweakHash` are used to implement the `TapTweak` trait on `UntweakedPublickey`
and `UntweakedKeypair`.
