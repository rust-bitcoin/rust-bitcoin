use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin::consensus::Decodable;
use bitcoin::hashes::hex::FromHex;
use bitcoin::Transaction;
use bitcoin_p2p_messages::message::InventoryPayload;
use bitcoin_p2p_messages::message_network::{ClientSoftwareVersion, UserAgent, UserAgentVersion};
use bitcoin_p2p_messages::{
    self, address, message, message_blockdata, message_network, Magic, ProtocolVersion,
    ServiceFlags,
};

const SOFTWARE_VERSION: ClientSoftwareVersion =
    ClientSoftwareVersion::SemVer { major: 0, minor: 1, revision: 0 };
const USER_AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(SOFTWARE_VERSION);
const SOFTWARE_NAME: &str = "rust-client";

#[allow(clippy::too_many_lines)]
fn main() {
    // This example connects to a node and broadcasts a raw transaction.
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: cargo run --example broadcast_tx -- <address> <network> <raw_tx_hex>");
        process::exit(1);
    }

    let str_address = &args[1];
    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("error parsing address: {error:?}");
        process::exit(1);
    });

    let network_name = &args[2];
    let magic = match network_name.as_str() {
        "bitcoin" => Magic::BITCOIN,
        "testnet" => Magic::TESTNET3,
        "signet" => Magic::SIGNET,
        "regtest" => Magic::REGTEST,
        _ => {
            eprintln!("unknown network: {}", network_name);
            process::exit(1);
        }
    };

    let raw_tx_hex = &args[3];
    // Use Vec::from_hex from hashes crate trait
    let tx_bytes = Vec::from_hex(raw_tx_hex).unwrap_or_else(|e| {
        eprintln!("Invalid hex string: {}", e);
        process::exit(1);
    });
    let tx: Transaction =
        Decodable::consensus_decode(&mut tx_bytes.as_slice()).unwrap_or_else(|e| {
            eprintln!("Invalid transaction data: {}", e);
            process::exit(1);
        });
    let txid = tx.compute_txid();
    println!("Parsed transaction with TXID: {}", txid);

    let version_message = build_version_message(address, magic);
    let first_message = message::RawNetworkMessage::new(magic, version_message);

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            // Send Version
            encoding::encode_to_writer(&first_message, &mut stream).unwrap();
            println!("Sent version message");

            // Setup StreamReader
            let read_stream = stream.try_clone().unwrap();
            let mut stream_reader = BufReader::new(read_stream);

            loop {
                // Loop and retrieve new messages
                match encoding::decode_from_read::<message::RawNetworkMessage, _>(
                    &mut stream_reader,
                ) {
                    Ok(reply) => {
                        match reply.payload() {
                            message::NetworkMessage::Version(_) => {
                                println!("Received version message");
                                let verack_message = message::RawNetworkMessage::new(
                                    magic,
                                    message::NetworkMessage::Verack,
                                );
                                encoding::encode_to_writer(&verack_message, &mut stream).unwrap();
                                println!("Sent verack message");
                            }
                            message::NetworkMessage::Verack => {
                                println!("Received verack message");

                                // Handshake complete. Announce the transaction.
                                let inv_item = message_blockdata::Inventory::Transaction(txid);
                                let inv_msg =
                                    message::NetworkMessage::Inv(InventoryPayload(vec![inv_item]));
                                let msg = message::RawNetworkMessage::new(magic, inv_msg);
                                encoding::encode_to_writer(&msg, &mut stream).unwrap();
                                println!("Announced transaction {} via INV", txid);
                            }
                            message::NetworkMessage::GetData(inventory) => {
                                // Check if the peer is requesting our transaction
                                for item in &inventory.0 {
                                    if let message_blockdata::Inventory::Transaction(
                                        requested_txid,
                                    ) = item
                                    {
                                        if *requested_txid == txid {
                                            println!("Peer requested our transaction. Sending TX data...");
                                            let tx_msg = message::NetworkMessage::Tx(tx.clone());
                                            let msg =
                                                message::RawNetworkMessage::new(magic, tx_msg);
                                            encoding::encode_to_writer(&msg, &mut stream).unwrap();
                                            println!("Sent TX message.");
                                        }
                                    }
                                }
                            }
                            message::NetworkMessage::Ping(nonce) => {
                                let pong = message::RawNetworkMessage::new(
                                    magic,
                                    message::NetworkMessage::Pong(*nonce),
                                );
                                encoding::encode_to_writer(&pong, &mut stream).unwrap();
                            }
                            message::NetworkMessage::Reject(reject) => {
                                // Simple string comparison to avoid type mismatch issues for now
                                if reject.hash.to_string() == txid.to_string() {
                                    println!("Transaction REJECTED by peer!");
                                    println!("Code: {:?}", reject.ccode);
                                    println!("Reason: {}", reject.reason);
                                    process::exit(1);
                                }
                            }
                            message::NetworkMessage::Inv(inv) => {
                                // If we see our own TXID announced back to us, it means propagation is working!
                                for item in &inv.0 {
                                    if let message_blockdata::Inventory::Transaction(inv_txid) =
                                        item
                                    {
                                        if *inv_txid == txid {
                                            println!("SUCCESS: Peer announced our transaction {} back to us!", txid);
                                            println!(
                                                "The transaction has been accepted by the node."
                                            );
                                            process::exit(0);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("Error decoding message: {:?}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("failed to open connection: {}", e);
        }
    }
}

fn build_version_message(address: SocketAddr, magic: Magic) -> message::NetworkMessage {
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // Use modern protocol version
    let protocol_version = if magic == Magic::SIGNET {
        ProtocolVersion::from_nonstandard(70014)
    } else {
        ProtocolVersion::from_nonstandard(70015)
    };

    let services = ServiceFlags::NONE;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time error").as_secs();
    let addr_recv = address::Address::new(&address, ServiceFlags::NONE);
    let addr_from = address::Address::new(&my_address, ServiceFlags::NONE);
    let nonce: u64 = 42;
    let start_height: i32 = 0;
    let user_agent = UserAgent::new(SOFTWARE_NAME, &USER_AGENT_VERSION);

    // Relay must be true to participate in tx propagation
    let mut msg = message_network::VersionMessage::new(
        protocol_version,
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    );
    msg.relay = true;

    message::NetworkMessage::Version(msg)
}
