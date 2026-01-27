# Rust Bitcoin Peer to Peer Message Types

This crate provides data types used in the Bitcoin peer-to-peer protocol.

## Examples

This crate includes several examples demonstrating how to interact with the Bitcoin P2P network.

You can run these examples using `cargo run --example <example_name> -- <args>`.

### Common Arguments
Most examples require a target node address and a network name.
- **Address**: `IP:PORT` (e.g., `127.0.0.1:18444` for Regtest or `127.0.0.1:8333` for Mainnet)
- **Network**: `bitcoin`, `testnet`, `signet`, or `regtest`

### List of Examples

#### 1. Handshake (`handshake.rs`)
Performs a version handshake with a node and prints its version information.
```sh
cargo run --example handshake -- 127.0.0.1:18444 regtest
```

#### 2. Get Headers (`get_headers.rs`)
Connects to a node, performs a handshake, and requests block headers.
```sh
cargo run --example get_headers -- 127.0.0.1:18444 regtest
```

#### 3. Get Blocks (`get_blocks.rs`)
Requests full block data for a range of blocks.
```sh
cargo run --example get_blocks -- 127.0.0.1:18444 regtest
```

#### 4. Get Addresses (`get_addr.rs`)
Requests a list of known peer addresses from the node.
```sh
cargo run --example get_addr -- 127.0.0.1:18444 regtest
```

#### 5. Ping/Pong (`ping_pong.rs`)
Continuously exchanges `ping` and `pong` messages to measure round-trip time (RTT).
```sh
cargo run --example ping_pong -- 127.0.0.1:18444 regtest
```

#### 6. Mempool Monitor (`mempool_monitor.rs`)
Connects to a node and listens for new transaction announcements (`inv` messages).
```sh
cargo run --example mempool_monitor -- 127.0.0.1:18444 regtest
```

#### 7. Broadcast Transaction (`broadcast_tx.rs`)
Broadcasts a raw signed transaction to the network.
```sh
# Arguments: <address> <network> <raw_tx_hex>
cargo run --example broadcast_tx -- 127.0.0.1:18444 regtest <RAW_HEX_STRING>
```