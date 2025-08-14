# rust-bitcoin dependency graph

This was made manually based on `./dependency-graph-raw`. 

To see if anything has changed you can diff that file against the output of:

  `cargo tree --all-features --edges=no-dev,no-build --format={lib}`


```
hex_conservative
  ├── arrayvec
  └── serde (elided)

bitcoin_internals
    ├── bincode <elided>
    ├── hex_conservative
    ├── serde 
    └── serde_json <elided>

bitcoin_io
  └── bitcoin_internals

bitcoin_hashes
  ├── bitcoin_internals
  ├── bitcoin_io
  ├── hex_conservative
  └── serde

bitcoin_consensus_encoding_unbuffered_io
  ├── bitcoin_hashes
  ├── bitcoin_internals
  ├── bitcoin_io
  └── hex_conservative

secp256k1
├── bitcoin_hashes
├── rand <elided>
├── secp256k1_sys
└── serde

base58ck
  ├── bitcoin_hashes
  └── bitcoin_internals

bitcoin_units
  ├── arbitrary
  ├── bitcoin_consensus_encoding_unbuffered_io
  ├── bitcoin_internals
  ├── bitcoin_io
  └── serde

bitcoin_primitives
  ├── arbitrary
  ├── arrayvec
  ├── bitcoin_consensus_encoding_unbuffered_io
  ├── bitcoin_internals
  ├── bitcoin_io
  ├── bitcoin_units
  ├── bitcoin_hashes
  ├── hex_conservative
  └── serde

bitcoin_addresses <crate is empty>

bitcoin_p2p_messages
  ├── bitcoin
  ├── bitcoin_consensus_encoding_unbuffered_io
  ├── bitcoin_internals
  ├── bitcoin_io
  ├── bitcoin_units
  ├── bitcoin_hashes
  └── hex_conservative

bitcoin
├── arbitrary
├── base58ck
├── base64
├── bech32
├── bitcoin_consensus_encoding_unbuffered_io
├── bitcoin_internals
├── bitcoin_io
├── bitcoin_primitives
├── bitcoin_units
├── bitcoin_hashes
├── bitcoinconsensus
├── hex_conservative
├── secp256k1
└── serde

```