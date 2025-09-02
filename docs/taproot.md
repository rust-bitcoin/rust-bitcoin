# Taproot

The `Taproot` code was left in `bitcoin` during the creation of
`primitives` because it is not as close to stable.

Furthermore the Taproot stuff is quite entangled in various places
throughout the codebase which in turn entangles the `secp256k1`
dependency.

We likely need to tease apart the Taproot stuff and disentangle the
bits we aren't yet willing to stabilize. Because of the entanglement
this effects various other crates (`psbt`, `crypto`) as well as the
stabilization efforts of script extension methods.

