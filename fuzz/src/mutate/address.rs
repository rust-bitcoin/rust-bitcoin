//! Mutator for address strings.
//!
//! bech32's checksum is a BCH code, and base58's is four bytes of double SHA256 over a
//! positional radix encoding. Neither is invertible by byte mutation, so an unaided fuzzer
//! essentially never produces a parsable address and the whole segwit path goes unexercised.
//!
//! So rather than mutate the string, this mutator decodes it into a record, mutates the
//! record, and re-encodes.

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{self, Bech32, Bech32m, Fe32, Hrp};

use super::{Mutate, Rng};

/// Longest program the unchecked segwit encoder takes without silently truncating.
///
/// It writes into a fixed 90 byte buffer and drops whatever does not fit, which would leave a
/// string whose checksum is wrong for the wrong reason. The worst case is the longest HRP:
/// 4 (`bcrt`) + 1 separator + 1 version + ceil(48 * 8 / 5) = 77 data + 6 checksum = 89.
const MAX_PROGRAM: usize = 48;

/// Longest string `Address::from_base58_str` will look at before giving up.
const MAX_BASE58_LEN: usize = 50;

/// Length of the hash in a base58 address payload.
const BASE58_HASH_LEN: usize = 20;

/// The HRPs `KnownHrp::from_hrp` accepts.
const HRPS: [Hrp; 3] = [bech32::hrp::BC, bech32::hrp::TB, bech32::hrp::BCRT];

/// The prefix bytes `Address::from_base58_str` accepts.
const BASE58_PREFIXES: [u8; 4] = [0x00, 0x05, 0x6F, 0xC4];

/// Encodes a base58check payload, appending its checksum.
fn base58_encode(payload: &[u8]) -> String {
    bitcoin::base58::Base58CkString::encode_unbounded(payload).as_str().into()
}

/// Decodes a base58check string, returning the payload without its checksum.
fn base58_decode(s: &str) -> Option<Vec<u8>> { bitcoin::base58::decode_check(s).ok() }

/// What kind of address a record describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// A valid segwit address.
    Segwit,
    /// A segwit address with a correct checksum but an invalid witness program, which is what
    /// reaches the error paths behind `bech32::segwit::decode`.
    SegwitNearMiss,
    /// A base58check address.
    Base58,
}

impl Form {
    /// Picks a form, weighted towards valid segwit addresses: those are the ones the target
    /// could never reach on its own, and the only ones its roundtrip assertion runs on.
    fn pick(rng: &mut Rng) -> Self {
        match rng.below(4) {
            0 | 1 => Self::Segwit,
            2 => Self::SegwitNearMiss,
            _ => Self::Base58,
        }
    }
}

/// The decoded form of an address, which is what actually gets mutated.
struct Record {
    form: Form,
    /// Index into [`HRPS`].
    hrp: usize,
    uppercase: bool,
    /// Whether to build a base58 payload the parser is bound to reject.
    malform: bool,
    /// Witness version for the segwit forms, prefix byte for base58.
    version: u8,
    program: [u8; MAX_PROGRAM],
    program_len: usize,
}

impl Record {
    fn new(form: Form, hrp: usize, version: u8, program: &[u8]) -> Self {
        let mut record = Self {
            form,
            hrp,
            uppercase: false,
            malform: false,
            version,
            program: [0; MAX_PROGRAM],
            program_len: program.len().min(MAX_PROGRAM),
        };
        record.program[..record.program_len].copy_from_slice(&program[..record.program_len]);
        record
    }

    fn program(&self) -> &[u8] { &self.program[..self.program_len] }
}

/// Mutates an address by decoding it, mutating the decoded form, and re-encoding.
pub fn mutate_payload(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    builtin_mutate: Mutate,
) -> usize {
    let mut rng = Rng::new(seed);

    // Keep a share of plain mutations, so inputs that are not addresses at all, and the error
    // paths only they reach, do not drop out of the corpus.
    if rng.one_in(8) {
        return builtin_mutate(data, size, max_size);
    }

    // An input that is not an address at all seeds a record from its raw bytes. The shape is
    // drawn at random rather than fixed, so that exploration from an empty corpus is not stuck
    // on one kind of address.
    let mut record =
        core::str::from_utf8(&data[..size]).ok().and_then(decode).unwrap_or_else(|| {
            let form = Form::pick(&mut rng);
            let hrp = rng.below(HRPS.len());
            let version = rng.next_u64() as u8;
            Record::new(form, hrp, version, &data[..size])
        });

    // Nudge the shape now and then. It is mostly carried over from the input, so that progress
    // on one kind of address compounds instead of being re-rolled on every mutation.
    if rng.one_in(8) {
        record.form = Form::pick(&mut rng);
    }
    if rng.one_in(8) {
        record.hrp = rng.below(HRPS.len());
    }
    if rng.one_in(8) {
        record.uppercase = rng.one_in(2);
    }
    if rng.one_in(8) {
        record.malform = rng.one_in(2);
    }
    if rng.one_in(8) {
        record.version = rng.next_u64() as u8;
    }

    // `program` is `MAX_PROGRAM` long and `program_len` never exceeds it.
    let program_len = builtin_mutate(&mut record.program, record.program_len, MAX_PROGRAM);
    record.program_len = program_len;

    match encode(&record) {
        Some(address) if address.len() <= max_size => {
            data[..address.len()].copy_from_slice(address.as_bytes());
            address.len()
        }
        _ => builtin_mutate(data, size, max_size),
    }
}

/// Rebuilds a record from an already-encoded address.
///
/// Returns `None` if `s` is not one, in which case the caller starts a record from scratch.
fn decode(s: &str) -> Option<Record> {
    let uppercase = s.bytes().any(|byte| byte.is_ascii_uppercase());

    if let Ok((hrp, version, program)) = bech32::segwit::decode(s) {
        let mut record = Record::new(Form::Segwit, hrp_index(hrp), version.to_u8(), &program);
        record.uppercase = uppercase;
        return Some(record);
    }

    // A near miss does not survive `segwit::decode`, which validates the witness program. Take
    // it apart at the checksum layer instead, so those inputs keep a lineage of their own
    // rather than being rediscovered from scratch every time.
    if let Ok(mut checked) =
        CheckedHrpstring::new::<Bech32m>(s).or_else(|_| CheckedHrpstring::new::<Bech32>(s))
    {
        if let Some(version) = checked.remove_witness_version() {
            let program = checked.byte_iter().collect::<Vec<u8>>();
            let mut record = Record::new(
                Form::SegwitNearMiss,
                hrp_index(checked.hrp()),
                version.to_u8(),
                &program,
            );
            record.uppercase = uppercase;
            return Some(record);
        }
    }

    // `from_base58_str` gives up past this length, and base58 decoding is quadratic in it, so
    // there is nothing to gain by decoding a longer string.
    if s.len() > MAX_BASE58_LEN {
        return None;
    }

    let payload = base58_decode(s)?;
    let (prefix, hash) = payload.split_first()?;

    let mut record = Record::new(Form::Base58, 0, *prefix, hash);
    record.malform = hash.len() != BASE58_HASH_LEN || !BASE58_PREFIXES.contains(prefix);
    Some(record)
}

/// Encodes a record, or returns `None` if it does not describe an encodable address.
fn encode(record: &Record) -> Option<String> {
    let hrp = HRPS[record.hrp];

    match record.form {
        Form::Segwit => {
            let version =
                Fe32::try_from(record.version % 17).expect("0..17 are valid field elements");
            let mut program = record.program().to_vec();
            program.resize(valid_program_len(version, program.len()), 0);

            let address = bech32::segwit::encode(hrp, version, &program).ok()?;
            Some(cased(address, record.uppercase))
        }
        Form::SegwitNearMiss => {
            // Mostly a legal version paired with an illegal program length: that clears the
            // version check and the checksum, and so actually reaches
            // `validate_witness_program_length`. A version above 16 is rejected before the
            // checksum is even looked at, making it a much shallower probe.
            let version =
                if record.version >= 0xF0 { record.version % 32 } else { record.version % 17 };
            let version = Fe32::try_from(version).expect("0..32 are valid field elements");

            let mut address = String::new();
            bech32::segwit::encode_lower_to_fmt_unchecked(
                &mut address,
                hrp,
                version,
                record.program(),
            )
            .ok()?;
            Some(cased(address, record.uppercase))
        }
        Form::Base58 => {
            let mut payload = vec![prefix(record.version, record.malform)];
            let mut hash = record.program().to_vec();
            hash.resize(base58_hash_len(hash.len(), record.malform), 0);
            payload.extend_from_slice(&hash);

            Some(base58_encode(&payload))
        }
    }
}

/// The index of `hrp` in [`HRPS`], defaulting to mainnet for anything else.
fn hrp_index(hrp: Hrp) -> usize { HRPS.iter().position(|candidate| *candidate == hrp).unwrap_or(0) }

/// Clamps a program to a length that is legal for `version`.
fn valid_program_len(version: Fe32, len: usize) -> usize {
    if version == bech32::segwit::VERSION_0 {
        if len >= 32 {
            32
        } else {
            20
        }
    } else {
        len.clamp(2, 40)
    }
}

/// The version byte of a base58 payload.
///
/// Usually one the parser recognises, so that the address is worth parsing at all, and
/// occasionally not, so that `InvalidLegacyPrefixError` stays reachable.
fn prefix(version: u8, malform: bool) -> u8 {
    if malform {
        version
    } else {
        BASE58_PREFIXES[usize::from(version) % BASE58_PREFIXES.len()]
    }
}

/// The hash length of a base58 payload.
///
/// Usually 20, the only length the parser accepts, and occasionally not, so that
/// `InvalidBase58PayloadLengthError` stays reachable.
fn base58_hash_len(len: usize, malform: bool) -> usize {
    if malform {
        len.min(MAX_PROGRAM)
    } else {
        BASE58_HASH_LEN
    }
}

/// Uppercases a bech32 string when the record asks for it.
///
/// bech32 permits an all-uppercase encoding, and parsing one is a distinct path.
fn cased(address: String, uppercase: bool) -> String {
    if uppercase {
        address.to_uppercase()
    } else {
        address
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::address::{Address, NetworkUnchecked};

    use super::*;

    /// A mainnet P2WPKH address. bech32 involves no hashing, so this is stable regardless of
    /// whether the tests are built with `--cfg=hashes_fuzz`.
    const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    /// Stands in for the built-in mutator, changing nothing.
    fn identity(_: &mut [u8], size: usize, max_size: usize) -> usize { size.min(max_size) }

    /// Stands in for the built-in mutator, overwriting the buffer with a known pattern.
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

    fn parses(bytes: &[u8]) -> bool {
        core::str::from_utf8(bytes)
            .ok()
            .is_some_and(|s| s.parse::<Address<NetworkUnchecked>>().is_ok())
    }

    /// One valid address of each shape the mutator can produce.
    fn samples() -> Vec<String> {
        let p2pkh = {
            let mut payload = vec![BASE58_PREFIXES[0]];
            payload.extend_from_slice(&[4; BASE58_HASH_LEN]);
            base58_encode(&payload)
        };

        vec![
            P2WPKH.to_owned(),
            bech32::segwit::encode(bech32::hrp::BC, Fe32::Q, &[1; 20]).unwrap(),
            bech32::segwit::encode(bech32::hrp::TB, Fe32::P, &[2; 32]).unwrap(),
            bech32::segwit::encode(bech32::hrp::BCRT, Fe32::Q, &[3; 32]).unwrap(),
            p2pkh,
        ]
    }

    #[test]
    fn decode_then_encode_is_the_identity() {
        for address in samples() {
            let record = decode(&address).expect("{address} should decode");
            assert_eq!(encode(&record).as_deref(), Some(address.as_str()));
        }
    }

    #[test]
    fn samples_are_addresses_in_the_first_place() {
        for address in samples() {
            assert!(parses(address.as_bytes()), "{address} is not a valid address");
        }
    }

    #[test]
    fn a_near_miss_keeps_its_lineage() {
        // Witness version 0 with a 21 byte program: `segwit::decode` refuses it, so recovering
        // the record has to go through the checksum layer instead.
        let record = Record::new(Form::SegwitNearMiss, 0, 0, &[7; 21]);
        let address = encode(&record).expect("near miss should encode");

        let back = decode(&address).expect("a near miss should still rebuild a record");
        assert_eq!(back.form, Form::SegwitNearMiss);
        assert_eq!(back.version, 0);
        assert_eq!(back.program(), &[7; 21]);
    }

    #[test]
    fn a_near_miss_is_rejected_for_its_structure_and_not_its_checksum() {
        let record = Record::new(Form::SegwitNearMiss, 0, 0, &[7; 21]);
        let address = encode(&record).expect("near miss should encode");

        // Recovering it above proves the checksum is correct, so this rejection can only be
        // the witness program length rule.
        assert!(!parses(address.as_bytes()), "{address} was supposed to be rejected");
    }

    #[test]
    fn most_mutations_are_still_parsable_addresses() {
        let parsed =
            (0..512).filter(|&seed| parses(&run(P2WPKH.as_bytes(), 128, seed, fill))).count();

        // The rest are the deliberate share of raw mutations, plus the near-miss form.
        assert!(parsed > 320, "only {parsed} of 512 mutations parsed as an address");
    }

    #[test]
    fn every_form_is_reachable() {
        let mut seen = std::collections::BTreeSet::new();

        for seed in 0..512 {
            let out = run(P2WPKH.as_bytes(), 128, seed, fill);
            if let Some(record) = core::str::from_utf8(&out).ok().and_then(decode) {
                seen.insert(format!("{:?}", record.form));
            }
        }

        assert_eq!(seen.len(), 3, "only reached {seen:?}");
    }

    #[test]
    fn uppercase_addresses_are_produced_and_parse() {
        let mut record = Record::new(Form::Segwit, 0, 0, &[7; 20]);
        record.uppercase = true;

        let address = encode(&record).expect("should encode");
        assert_eq!(address, address.to_uppercase());
        assert!(parses(address.as_bytes()), "{address} should parse");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let inputs: [&[u8]; 5] = [b"", b"\xff\xfe\xfd", b"bc1", &[0x41; 200], P2WPKH.as_bytes()];

        for input in inputs {
            for seed in 0..64 {
                for builtin_mutate in [identity as Mutate, fill as Mutate] {
                    for max_size in [0, 1, 20, 50, 128, 4096] {
                        let _ = run(input, max_size, seed, builtin_mutate);
                    }
                }
            }
        }
    }

    #[test]
    fn base58_codec_round_trips() {
        let payload = [0x00u8; 21];
        let encoded = base58_encode(&payload);

        assert_eq!(base58_decode(&encoded).as_deref(), Some(&payload[..]));
    }

    /// The base58 checksum of both crate versions has to agree, or the `bitcoin 0.32` target
    /// would be handed addresses its own parser rejects.
    #[test]
    fn both_crate_versions_agree_on_base58() {
        for prefix in BASE58_PREFIXES {
            let mut payload = vec![prefix];
            payload.extend_from_slice(&[7; BASE58_HASH_LEN]);

            assert_eq!(base58_encode(&payload), bitcoin_0_32::base58::encode_check(&payload));
        }
    }
}
