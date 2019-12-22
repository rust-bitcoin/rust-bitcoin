#![cfg(test)]

use hashes::Hash;
use network::message_network::{VersionMessage, Reject, RejectReason};
use network::Address;
use network::message_blockdata::{InvType, Inventory, GetBlocksMessage, GetHeadersMessage};
use network::constants::{ServiceFlags};
use secp256k1::rand::distributions::{Distribution, Standard, Alphanumeric};
use secp256k1::rand::Rng;
use secp256k1::rand::seq::SliceRandom;
use std::iter;
use {Transaction, TxIn, OutPoint, Script};
use ::{TxOut, Block};
use BlockHeader;
use network::message_filter::{GetCFilters, CFilter, GetCFHeaders, CFHeaders, GetCFCheckpt, CFCheckpt};
use network::message::{CommandString, NetworkMessage};

const ALLOC_LIMIT: usize = 64;


// TODO: Replace ASCII with UTF-8.
fn gen_string<R: Rng + ?Sized>(rng: &mut R) -> String {
    let size = rng.gen_range(0, ALLOC_LIMIT);
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(size)
        .collect()
}

pub fn gen_vec<R: Rng + ?Sized, T>(rng: &mut R) -> Vec<T> where Standard: Distribution<T> {
    let size = rng.gen_range(0, ALLOC_LIMIT);
    let mut vec = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(rng.gen());
    }
    vec
}

fn gen_vec_of_vec<R: Rng + ?Sized, T>(rng: &mut R) -> Vec<Vec<T>> where Standard: Distribution<T> {
    let outer_size = rng.gen_range(0, ALLOC_LIMIT);
    let mut outer_vec = Vec::with_capacity(outer_size);
    for _ in 0..outer_size {
        let inner_size = rng.gen_range(0, ALLOC_LIMIT);
        let mut inner_vec = Vec::with_capacity(inner_size);
        for _ in 0..inner_size {
            inner_vec.push(rng.gen());
        }
        outer_vec.push(inner_vec);
    }
    outer_vec
}

fn gen_vec_hash<R: Rng + ?Sized, H: Hash>(rng: &mut R) -> Vec<H> {
    let size = rng.gen_range(0, ALLOC_LIMIT);
    let mut vec = Vec::with_capacity(size);
    for _ in 0..size {
        vec.push(gen_hash(rng))
    }
    vec
}

fn gen_hash<R: Rng + ?Sized, H: Hash>(rng: &mut R) -> H {
    let mut hash_vec = vec![0u8; H::LEN];
    rng.fill_bytes(&mut hash_vec[..]);
    H::from_slice(&hash_vec).unwrap() // It's the right length. should never fail.
}

impl Distribution<ServiceFlags> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ServiceFlags {
        ServiceFlags::from(rng.next_u64())
    }
}

impl Distribution<InvType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> InvType {
        // This is meant to force compile time check that the enum definition hasn't changed.
        let a = InvType::Error;
        match a {
            InvType::Error => (),
            InvType::Transaction => (),
            InvType::Block => (),
            InvType::WitnessBlock => (),
            InvType::WitnessTransaction => (),
        };
        // TODO: FIXME when #369 is resolved.
        match rng.gen_range(0, 3) {
            0 => InvType::Error,
            1 => InvType::Transaction,
            2 => InvType::Block,
//            3 => InvType::WitnessBlock,
//            4 => InvType::WitnessTransaction,
            _ => panic!("Please update the random generation for InvType"),
        }
    }
}

impl Distribution<RejectReason> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RejectReason {
        // This is meant to force compile time check that the enum definition hasn't changed.
        let a = RejectReason::Malformed;
        match a {
            RejectReason::Malformed => (),
            RejectReason::Invalid => (),
            RejectReason::Obsolete => (),
            RejectReason::Duplicate => (),
            RejectReason::NonStandard => (),
            RejectReason::Dust => (),
            RejectReason::Fee => (),
            RejectReason::Checkpoint => (),
        };
        match rng.gen_range(0, 8) {
            0 => RejectReason::Malformed,
            1 => RejectReason::Invalid,
            2 => RejectReason::Obsolete,
            3 => RejectReason::Duplicate,
            4 => RejectReason::NonStandard,
            5 => RejectReason::Dust,
            6 => RejectReason::Fee,
            7 => RejectReason::Checkpoint,
            _ => panic!("Please update the random generation for RejectReason"),
        }
    }
}

impl Distribution<Address> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Address {
        Address {
            services: rng.gen(),
            address: rng.gen(),
            port: rng.gen(),
        }
    }
}

impl Distribution<Inventory> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Inventory {
        Inventory {
            inv_type: rng.gen(),
            hash: gen_hash(rng),
        }
    }
}

impl Distribution<GetBlocksMessage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GetBlocksMessage {
        GetBlocksMessage {
            version: rng.gen(),
            locator_hashes: gen_vec_hash(rng),
            stop_hash: gen_hash(rng),
        }
    }
}

impl Distribution<GetHeadersMessage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GetHeadersMessage {
        GetHeadersMessage {
            version: rng.gen(),
            locator_hashes: gen_vec_hash(rng),
            stop_hash: gen_hash(rng),
        }
    }
}

impl Distribution<TxIn> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TxIn {
        TxIn {
            previous_output: rng.gen(),
            script_sig: rng.gen(),
            sequence: rng.gen(),
            witness: gen_vec_of_vec(rng),
        }
    }
}

impl Distribution<TxOut> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TxOut {
        TxOut {
            value: rng.gen(),
            script_pubkey: rng.gen(),
        }
    }
}

impl Distribution<OutPoint> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OutPoint {
        OutPoint {
            txid: gen_hash(rng),
            vout: rng.gen(),
        }
    }
}

impl Distribution<Script> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Script {
        Script::from(gen_vec(rng))
    }
}

impl Distribution<Transaction> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Transaction {
        Transaction {
            version: rng.gen(),
            lock_time: rng.gen(),
            input: gen_vec(rng),
            output: gen_vec(rng),
        }
    }
}

impl Distribution<BlockHeader> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockHeader {
        BlockHeader {
            version: rng.gen(),
            prev_blockhash: gen_hash(rng),
            merkle_root: gen_hash(rng),
            time: rng.gen(),
            bits: rng.gen(),
            nonce: rng.gen(),
        }
    }
}

impl Distribution<Block> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        Block {
            header: rng.gen(),
            txdata: gen_vec(rng),
        }
    }
}

impl Distribution<GetCFilters> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GetCFilters {
        GetCFilters {
            filter_type: rng.gen(),
            start_height: rng.gen(),
            stop_hash: gen_hash(rng),
        }
    }
}

impl Distribution<CFilter> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CFilter {
        CFilter {
            filter_type: rng.gen(),
            block_hash: gen_hash(rng),
            filter: gen_vec(rng),
        }
    }
}

impl Distribution<GetCFHeaders> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GetCFHeaders {
        GetCFHeaders {
            filter_type: rng.gen(),
            start_height: rng.gen(),
            stop_hash: gen_hash(rng),
        }
    }
}

impl Distribution<CFHeaders> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CFHeaders {
        CFHeaders {
            filter_type: rng.gen(),
            stop_hash: gen_hash(rng),
            previous_filter: gen_hash(rng),
            filter_hashes: gen_vec_hash(rng),
        }
    }
}

impl Distribution<GetCFCheckpt> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GetCFCheckpt {
        GetCFCheckpt {
            filter_type: rng.gen(),
            stop_hash: gen_hash(rng),
        }
    }
}

impl Distribution<CFCheckpt> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CFCheckpt {
        CFCheckpt {
            filter_type: rng.gen(),
            stop_hash: gen_hash(rng),
            filter_headers: gen_vec_hash(rng),
        }
    }
}

impl Distribution<CommandString> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CommandString {
        NetworkMessage::possibilites().choose(rng).unwrap().clone() // Can never fail. the array isn't empty.
    }
}

impl Distribution<Reject> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Reject {
        Reject {
            message: rng.gen(),
            ccode: rng.gen(),
            reason: gen_string(rng).into(),
            hash: gen_hash(rng),
        }
    }
}


impl Distribution<VersionMessage> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> VersionMessage {
        VersionMessage {
            version: rng.gen(),
            services: rng.gen(),
            timestamp: rng.gen(),
            receiver: rng.gen(),
            sender: rng.gen(),
            nonce: rng.gen(),
            user_agent: gen_string(rng),
            start_height: rng.gen(),
            relay: rng.gen(),
        }
    }
}