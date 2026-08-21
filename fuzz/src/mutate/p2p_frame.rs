//! Mutator for the v1 p2p message frame.
//!
//! A frame is `magic[0..4] || command[4..16] || length[16..20] || checksum[20..24] || payload`.
//! Three things have to hold at once for one to decode: the command has to name a known
//! message, `length` has to equal the payload length exactly, and `checksum` has to be the
//! first four bytes of the payload's double SHA256. Mutating the payload breaks the last two
//! every time, which is why an unaided fuzzer never gets past the header and into the payload
//! parsers.
//!
//! This mutator confines mutation to the payload region and then rewrites `length` and
//! `checksum`, so the frame it hands back is always decodable.

use super::{Mutate, Rng};

/// Size of the v1 message header, in bytes.
pub const HEADER_LEN: usize = 24;

/// Every command accepted by `NetworkMessageDecoderInner::new` in `p2p/src/message.rs`.
///
/// No public API exposes this list, so it is duplicated here. Anything absent decodes to
/// `NetworkMessage::Unknown`, which means a stale entry costs a little fuzzing efficiency but
/// never correctness. `bitcoin 0.32` does not know `sendtxrcncl` or `feature` and treats them
/// as unknown commands.
pub const COMMANDS: [&str; 38] = [
    "version",
    "verack",
    "sendheaders",
    "mempool",
    "getaddr",
    "wtxidrelay",
    "filterclear",
    "sendaddrv2",
    "addr",
    "inv",
    "getdata",
    "notfound",
    "getblocks",
    "getheaders",
    "tx",
    "block",
    "headers",
    "ping",
    "pong",
    "merkleblock",
    "filterload",
    "filteradd",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "alert",
    "reject",
    "feefilter",
    "sendtxrcncl",
    "addrv2",
    "feature",
];

/// The payload size of each command that has exactly one.
///
/// A frame only decodes when the payload decoder consumes the region exactly: it stops at its
/// own natural size and `decode_from_slice` then rejects the leftovers. For these commands any
/// other length is wasted, so the mutator snaps to the one that can work. The
/// `fixed_payload_lengths_are_accurate` test checks every entry, which is what keeps the table
/// honest as the protocol grows.
const FIXED_PAYLOAD_LEN: [(&str, usize); 15] = [
    ("verack", 0),
    ("sendheaders", 0),
    ("mempool", 0),
    ("getaddr", 0),
    ("wtxidrelay", 0),
    ("filterclear", 0),
    ("sendaddrv2", 0),
    ("ping", 8),
    ("pong", 8),
    ("feefilter", 8),
    ("sendcmpct", 9),
    ("sendtxrcncl", 12),
    ("getcfcheckpt", 33),
    ("getcfilters", 37),
    ("getcfheaders", 37),
];

/// First four bytes of `sha256d(payload)`, as `p2p`'s private `sha2_checksum` computes it.
fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = bitcoin::hashes::sha256d::Hash::hash(payload).to_byte_array();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Mutates the payload of a v1 p2p frame, then repairs the header around it.
pub fn mutate_payload(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    builtin_mutate: Mutate,
) -> usize {
    // A frame needs a header and somewhere to put a payload. libFuzzer asserts `MaxSize > 0`
    // inside its own mutator, so an empty payload region is not something we can hand it.
    if max_size <= HEADER_LEN {
        return builtin_mutate(data, size, max_size);
    }

    // libFuzzer sizes `data` at `max(size, max_size)`, and `max_size > HEADER_LEN` above, so
    // the header is in bounds even when the input is shorter than one.
    let mut size = size;
    if size < HEADER_LEN {
        data[size..HEADER_LEN].fill(0);
        size = HEADER_LEN;
    }

    let mut rng = Rng::new(seed);

    // Mutate the header itself now and then. libFuzzer stops generating inputs of its own once
    // a custom mutator exists, so without this the command could only ever change by wholesale
    // replacement below, and the decoder's own header error paths, such as a non-ASCII command
    // or one with an interior NUL, would be unreachable.
    if rng.one_in(8) {
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&data[..HEADER_LEN]);
        builtin_mutate(&mut header, HEADER_LEN, HEADER_LEN);
        data[..HEADER_LEN].copy_from_slice(&header);
    }

    // Both arguments are within `data[HEADER_LEN..]`, whose length is
    // `max(size, max_size) - HEADER_LEN`.
    let mut payload_len =
        builtin_mutate(&mut data[HEADER_LEN..], size - HEADER_LEN, max_size - HEADER_LEN);

    // Swapping the command hands the payload to a different decoder, so do it rarely.
    if rng.one_in(16) {
        let command = rng.pick(&COMMANDS);
        data[4..16].fill(0);
        data[4..4 + command.len()].copy_from_slice(command.as_bytes());
    }

    // A command with a fixed size will only ever consume that many bytes, so snap the payload
    // to it rather than leaving the fuzzer to rediscover the one length that can work.
    if let Some(fixed) = fixed_payload_len(&data[4..16]) {
        if HEADER_LEN + fixed <= max_size {
            if fixed > payload_len {
                data[HEADER_LEN + payload_len..HEADER_LEN + fixed].fill(0);
            }
            payload_len = fixed;
        }
    }

    // Leave a frame broken now and then, for the same reason the header is mutated above: the
    // checksum and length error paths are only reachable if something still produces them.
    if !rng.one_in(32) {
        let length =
            u32::try_from(payload_len).expect("payload is bounded by libFuzzer's -max_len");
        data[16..20].copy_from_slice(&length.to_le_bytes());

        let checksum = checksum(&data[HEADER_LEN..HEADER_LEN + payload_len]);
        data[20..24].copy_from_slice(&checksum);
    }

    // Never exceeds `max_size`, so the caller's clamp cannot truncate the frame and undo the
    // length and checksum written above.
    HEADER_LEN + payload_len
}

/// The fixed payload size of the command named in a header's command field, if it has one.
fn fixed_payload_len(command: &[u8]) -> Option<usize> {
    let trimmed = command.split(|byte| *byte == 0).next()?;
    let command = core::str::from_utf8(trimmed).ok()?;

    FIXED_PAYLOAD_LEN.iter().find(|(name, _)| *name == command).map(|(_, len)| *len)
}

#[cfg(test)]
mod tests {
    use bitcoin_consensus_encoding::decode_from_slice;

    use super::*;

    /// Stands in for the built-in mutator, leaving the payload alone.
    fn identity(_: &mut [u8], size: usize, max_size: usize) -> usize { size.min(max_size) }

    /// Stands in for the built-in mutator, growing the payload to fill the space.
    fn fill(data: &mut [u8], _size: usize, max_size: usize) -> usize {
        for (i, byte) in data[..max_size].iter_mut().enumerate() {
            *byte = i as u8;
        }
        max_size
    }

    /// Runs the mutator the way libFuzzer would, and returns the mutated input.
    fn run(input: &[u8], max_size: usize, seed: u32, builtin_mutate: Mutate) -> Vec<u8> {
        // libFuzzer sizes the buffer at `max(size, max_size)`.
        let mut data = vec![0u8; input.len().max(max_size)];
        data[..input.len()].copy_from_slice(input);

        let len = mutate_payload(&mut data, input.len(), max_size, seed, builtin_mutate);
        assert!(len <= max_size, "returned {len} for a max_size of {max_size}");

        data.truncate(len);
        data
    }

    /// Whether a frame's length and checksum fields describe its payload.
    fn is_repaired(frame: &[u8]) -> bool {
        let payload = &frame[HEADER_LEN..];
        frame[16..20] == (payload.len() as u32).to_le_bytes() && frame[20..24] == checksum(payload)
    }

    /// A frame carrying a `verack`, which has an empty payload.
    fn verack() -> Vec<u8> {
        let mut frame = vec![0u8; HEADER_LEN];
        frame[4..10].copy_from_slice(b"verack");
        frame[20..24].copy_from_slice(&checksum(&[]));
        frame
    }

    #[test]
    fn the_header_almost_always_describes_the_payload() {
        let cases = [(0, 25), (5, 30), (24, 25), (24, 4096), (100, 30), (200, 200)];
        let (mut repaired, mut total) = (0, 0);

        for seed in 0..256 {
            for builtin_mutate in [identity as Mutate, fill as Mutate] {
                for (size, max_size) in cases {
                    let frame = run(&vec![0xAB; size], max_size, seed, builtin_mutate);
                    assert!(frame.len() >= HEADER_LEN);

                    total += 1;
                    repaired += usize::from(is_repaired(&frame));
                }
            }
        }

        // The rest are the deliberate share left broken, so the decoder's checksum and length
        // error paths stay reachable.
        assert!(repaired * 10 > total * 9, "only {repaired} of {total} frames were repaired");
        assert!(repaired < total, "no frame was left broken, so those error paths are dead");
    }

    #[test]
    fn a_repaired_frame_decodes() {
        let mut checked = 0;

        for seed in 0..256 {
            let frame = run(&verack(), 4096, seed, identity);

            // Skip the seeds that rewrote the header or deliberately left it broken.
            if &frame[4..10] != b"verack" || frame[10..16] != [0; 6] || !is_repaired(&frame) {
                continue;
            }

            decode_from_slice::<p2p::message::V1NetworkMessage>(&frame)
                .expect("a repaired verack frame should decode");
            checked += 1;
        }

        assert!(checked > 0, "every seed was skipped, so nothing was checked");
    }

    #[test]
    fn commands_are_valid_and_reach_a_real_parser() {
        for command in COMMANDS {
            assert!(command.is_ascii(), "{command} is not ASCII");
            assert!(command.len() <= 12, "{command} does not fit in a CommandString");

            let mut frame = vec![0u8; HEADER_LEN];
            frame[4..4 + command.len()].copy_from_slice(command.as_bytes());
            frame[20..24].copy_from_slice(&checksum(&[]));

            // An empty payload will not satisfy most of these, but a command the decoder does
            // not know is never a parse failure: it decodes to `Unknown`. So a command that
            // fails to decode here has definitely been dispatched to a real parser.
            if let Ok(message) = decode_from_slice::<p2p::message::V1NetworkMessage>(&frame) {
                assert_ne!(
                    message.payload().command().as_ref(),
                    "unknown",
                    "{command} is not in the decoder's dispatch table any more"
                );
            }
        }
    }

    #[test]
    fn fixed_payload_lengths_are_accurate() {
        for (command, len) in FIXED_PAYLOAD_LEN {
            assert!(COMMANDS.contains(&command), "{command} is not a known command");

            let mut frame = vec![0u8; HEADER_LEN + len];
            frame[4..4 + command.len()].copy_from_slice(command.as_bytes());
            frame[16..20].copy_from_slice(&(len as u32).to_le_bytes());
            let checksum = checksum(&frame[HEADER_LEN..]);
            frame[20..24].copy_from_slice(&checksum);

            let message = decode_from_slice::<p2p::message::V1NetworkMessage>(&frame)
                .unwrap_or_else(|e| {
                    panic!("{command} should decode with {len} payload bytes: {e:?}")
                });
            assert_eq!(message.payload().command().as_ref(), command);
        }
    }

    #[test]
    fn a_snapped_command_produces_a_decodable_frame() {
        // Every seed that swaps in a fixed-size command should also resize the payload to
        // match, so the frame it hands back decodes rather than tripping the checksum. The
        // payload starts out zeroed because snapping fixes the length, not the content, and an
        // arbitrary payload of the right length is still free to be an invalid message.
        for seed in 0..2_048 {
            let frame = run(&[0; 200], 4_096, seed, identity);
            let Some(fixed) = fixed_payload_len(&frame[4..16]) else { continue };

            if !is_repaired(&frame) {
                continue; // Deliberately left broken.
            }
            assert_eq!(frame.len(), HEADER_LEN + fixed, "payload was not snapped to fit");
            decode_from_slice::<p2p::message::V1NetworkMessage>(&frame)
                .expect("a snapped frame should decode");
        }
    }

    /// The checksum of both crate versions has to agree, or the `bitcoin 0.32` target would be
    /// handed frames its own decoder rejects.
    #[test]
    fn both_crate_versions_agree_on_the_checksum() {
        use bitcoin_0_32::hashes::Hash as _;

        for len in [0, 1, 31, 32, 33, 63, 64, 65, 200] {
            let payload = vec![0xAB; len];
            let hash = bitcoin_0_32::hashes::sha256d::Hash::hash(&payload).to_byte_array();

            assert_eq!(checksum(&payload), hash[..4], "mismatch on a {len} byte payload");
        }
    }

    #[test]
    fn tiny_max_size_falls_back_to_the_built_in_mutator() {
        for max_size in 0..=HEADER_LEN {
            let input = vec![0xAB; 40];
            let mut data = vec![0u8; input.len().max(max_size)];
            data[..input.len()].copy_from_slice(&input);

            let len = mutate_payload(&mut data, input.len(), max_size, 0, identity);
            assert!(len <= max_size);
        }
    }
}
