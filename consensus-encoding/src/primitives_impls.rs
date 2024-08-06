//! Decoders and encoders for types from [`bitcoin-primitives`](primitives).

use super::Decode;
use push_decode::encoders::IntEncoder;
use actual_primitives::{Sequence, absolute::LockTime};

mapped_decoder! {
    Sequence => #[derive(Default)] pub struct SequenceDecoder(<u32 as Decode>::Decoder) using Sequence;
}

encoder_newtype! {
    Sequence => pub struct SequenceEncoder(IntEncoder<u32>)
        map u32 as |sequence: &Sequence| sequence.to_consensus_u32();
}

mapped_decoder! {
    LockTime => #[derive(Default)] pub struct LockTimeDecoder(<u32 as Decode>::Decoder) using LockTime::from_consensus;
}

encoder_newtype! {
    LockTime => pub struct LockTimeEncoder(push_decode::encoders::IntEncoder<u32>) map u32 as |lock_time: &LockTime| lock_time.to_consensus_u32();
}

