use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

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
    // This example connects to a node, requests the mempool, and monitors for new transactions.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cargo run --example mempool_monitor -- <address> [network]");
        process::exit(1);
    }

    let str_address = &args[1];
    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("error parsing address: {error:?}");
        process::exit(1);
    });

    let network_name = if args.len() > 2 { &args[2] } else { "bitcoin" };
    let magic = match network_name {
        "bitcoin" => Magic::BITCOIN,
        "testnet" => Magic::TESTNET3,
        "signet" => Magic::SIGNET,
        "regtest" => Magic::REGTEST,
        _ => {
            eprintln!("unknown network: {}", network_name);
            process::exit(1);
        }
    };

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

                                // Handshake complete.
                                // We do not send Mempool message to avoid disconnection (some nodes disallow it).
                                // Instead, we rely on "relay=true" in Version message to receive new transactions.
                                println!("Handshake complete. Listening for new transactions...");
                            }
                            message::NetworkMessage::Inv(inv_msg) => {
                                let mut request_items = Vec::new();
                                for item in &inv_msg.0 {
                                    match item {
                                        message_blockdata::Inventory::Transaction(txid) => {
                                            println!("New Transaction announced: {}", txid);
                                            request_items.push(
                                                message_blockdata::Inventory::Transaction(*txid),
                                            );
                                        }
                                        message_blockdata::Inventory::Block(hash) => {
                                            println!("New Block announced: {}", hash);
                                        }
                                        _ => {}
                                    }
                                }

                                // If we found transactions, ask for them!
                                if !request_items.is_empty() {
                                    println!("Requesting {} transactions...", request_items.len());
                                    let get_data = InventoryPayload(request_items);
                                    let msg = message::RawNetworkMessage::new(
                                        magic,
                                        message::NetworkMessage::GetData(get_data),
                                    );
                                    encoding::encode_to_writer(&msg, &mut stream).unwrap();
                                }
                            }
                            message::NetworkMessage::Tx(tx) => {
                                let txid = tx.compute_txid();
                                println!(
                                    "Received Transaction: {} | Inputs: {} | Outputs: {}",
                                    txid,
                                    tx.inputs.len(),
                                    tx.outputs.len()
                                );
                            }
                            message::NetworkMessage::Ping(nonce) => {
                                // Respond to Ping with Pong to keep connection alive
                                let pong = message::RawNetworkMessage::new(
                                    magic,
                                    message::NetworkMessage::Pong(*nonce),
                                );
                                encoding::encode_to_writer(&pong, &mut stream).unwrap();
                                // println!("Received Ping, sent Pong");
                            }
                            _ => {
                                // println!("Received other message: {}", reply.cmd());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("\nError decoding message: {:?}", e);
                        eprintln!(
                            "---------------------------------------------------------------"
                        );
                        eprintln!("HINT: This error often happens if you try to connect to the RPC port (e.g., 8332) instead of the P2P port (e.g., 8333).");
                        eprintln!("The P2P protocol does NOT require a username/password.");
                        eprintln!("Please check your port and try again.");
                        eprintln!(
                            "---------------------------------------------------------------"
                        );
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
    msg.relay = true; // Enable transaction relay

    message::NetworkMessage::Version(msg)
}
