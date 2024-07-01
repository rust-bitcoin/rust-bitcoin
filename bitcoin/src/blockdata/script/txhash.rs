
#![allow(missing_docs)]

use std::borrow::Borrow;
use std::convert::TryInto;

use crate::{Script, Transaction, TxOut};
use crate::consensus::encode::Encodable;
use crate::hashes::{sha256, Hash, HashEngine};

pub const TXFS_VERSION: u8 = 1 << 0;
pub const TXFS_LOCKTIME: u8 = 1 << 1;
pub const TXFS_CURRENT_INPUT_IDX: u8 = 1 << 2;
pub const TXFS_CURRENT_INPUT_SPENTSCRIPT: u8 = 1 << 3;
pub const TXFS_CURRENT_INPUT_CONTROL_BLOCK: u8 = 1 << 4;
pub const TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS: u8 = 1 << 5;
// pub const TXFS_UNUSED: u8 = 1 << 6;
pub const TXFS_CONTROL: u8 = 1 << 7;

pub const TXFS_ALL: u8 = TXFS_VERSION
    | TXFS_LOCKTIME
    | TXFS_CURRENT_INPUT_IDX
    | TXFS_CURRENT_INPUT_SPENTSCRIPT
    | TXFS_CURRENT_INPUT_CONTROL_BLOCK
    | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS
    | TXFS_CONTROL;

pub const TXFS_INPUTS_PREVOUTS: u8 = 1 << 0;
pub const TXFS_INPUTS_SEQUENCES: u8 = 1 << 1;
pub const TXFS_INPUTS_SCRIPTSIGS: u8 = 1 << 2;
pub const TXFS_INPUTS_PREV_SCRIPTPUBKEYS: u8 = 1 << 3;
pub const TXFS_INPUTS_PREV_VALUES: u8 = 1 << 4;
pub const TXFS_INPUTS_TAPROOT_ANNEXES: u8 = 1 << 5;
pub const TXFS_OUTPUTS_SCRIPTPUBKEYS: u8 = 1 << 6;
pub const TXFS_OUTPUTS_VALUES: u8 = 1 << 7;

pub const TXFS_INPUTS_ALL: u8 = TXFS_INPUTS_PREVOUTS
    | TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_SCRIPTPUBKEYS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_INPUTS_TEMPLATE: u8 = TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_OUTPUTS_ALL: u8 = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES;

pub const TXFS_INOUT_NUMBER: u8 = 1 << 7;
pub const TXFS_INOUT_SELECTION_NONE: u8 = 0x00;
pub const TXFS_INOUT_SELECTION_CURRENT: u8 = 0x40;
pub const TXFS_INOUT_SELECTION_ALL: u8 = 0x3f;
pub const TXFS_INOUT_SELECTION_MODE: u8 = 1 << 6;
pub const TXFS_INOUT_LEADING_SIZE: u8 = 1 << 5;
pub const TXFS_INOUT_INDIVIDUAL_MODE: u8 = 1 << 5;
pub const TXFS_INOUT_SELECTION_MASK: u8 = 0xff ^ (1 << 7) ^ (1 << 6) ^ (1 << 5);


pub const TXFS_SPECIAL_ALL: [u8; 4] = [
    TXFS_ALL,
    TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];
pub const TXFS_SPECIAL_TEMPLATE: [u8; 4] = [
    TXFS_ALL,
    TXFS_INPUTS_TEMPLATE | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];


const LEADING_CACHE_INTERVAL: usize = 10;

const SHA256_EMPTY: sha256::Hash = sha256::Hash::const_hash(&[]);

trait VecExt<T: Default> {
    fn new_default(length: usize) -> Vec<T> {
        let mut ret = Vec::with_capacity(length);
        ret.resize_with(length, || Default::default());
        ret
    }
}
impl<T: Default> VecExt<T> for Vec<T> {}

trait IterExt {
    fn hash_sha256<H: Hash>(self) -> H;
}

impl<T: AsRef<[u8]>, I: Iterator<Item = T>> IterExt for I {
    fn hash_sha256<H: Hash>(self) -> H {
        let mut engine = H::engine();
        self.for_each(|e| engine.input(e.as_ref()));
        H::from_engine(engine)
    }
}

fn read_i7(input: u8) -> i8 {
    let masked = input & 0x7f;
    if (masked & 0x40) == 0 {
        masked as i8
    } else {
        0i8 - ((!(masked-1)) & 0x7f) as i8
    }
}

fn read_i15(input: u16) -> i16 {
    let masked = input & 0x7fff;
    if (masked & 0x4000) == 0 {
        masked as i16
    } else {
        0i16 - ((!(masked-1)) & 0x7fff) as i16
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum InOutSelector {
    None,
    All,
    Current,
    Leading(usize),
    Absolute(Vec<usize>),
    Relative(Vec<isize>),
}

impl InOutSelector {
    pub fn is_none(&self) -> bool {
        match self {
            Self::None => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct InputFields {
    pub number: bool,

    pub prevouts: bool,
    pub sequences: bool,
    pub script_sigs: bool,
    pub prevout_script_pubkeys: bool,
    pub prevout_values: bool,
    pub taproot_annexes: bool,

    pub selector: InOutSelector,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct OutputFields {
    pub number: bool,

    pub script_pubkeys: bool,
    pub values: bool,

    pub selector: InOutSelector,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TxFields {
    pub version: bool,
    pub lock_time: bool,
    pub current_input_idx: bool,
    pub current_input_spentscript: bool,
    pub current_input_control_block: bool,
    pub current_input_last_codeseparator_pos: bool,
    pub inputs: Option<InputFields>,
    pub outputs: Option<OutputFields>,
}

impl TxFields {
    fn parse_inout_selector(
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<Option<(bool, InOutSelector)>, &'static str> {
        let byte = match bytes.next() {
            Some(b) => b,
            None => return Ok(None),
        };
        let number = (byte & TXFS_INOUT_NUMBER) != 0;
        let selection = byte & (0xff ^ TXFS_INOUT_NUMBER);

        let selection = if selection == TXFS_INOUT_SELECTION_NONE {
            InOutSelector::None
        } else if selection == TXFS_INOUT_SELECTION_ALL {
            InOutSelector::All
        } else if selection == TXFS_INOUT_SELECTION_CURRENT {
            InOutSelector::Current
        } else if (selection & TXFS_INOUT_SELECTION_MODE) == 0 {
            // leading mode

            let count = if (selection & TXFS_INOUT_LEADING_SIZE) == 0 {
                (selection & TXFS_INOUT_SELECTION_MASK) as usize
            } else {
                if (selection & TXFS_INOUT_SELECTION_MASK) == 0 {
                    return Err("non-minimal leading selection")?;
                }

                let next = bytes.next().ok_or("missing second leading selection byte")?;
                (((selection & TXFS_INOUT_SELECTION_MASK) as usize) << 8) + (next as usize)
            };

            InOutSelector::Leading(count)
        } else {
            // individual mode

            let absolute = (selection & TXFS_INOUT_INDIVIDUAL_MODE) == 0;
            let count = (selection & TXFS_INOUT_SELECTION_MASK) as usize;
            if count == 0 {
                return Err("zero individual items selected")?;
            }

            let mut selected = Vec::with_capacity(count);
            while selected.len() < count {
                let first = bytes.next().ok_or("missing individual indices")?;
                let single_byte = (first & 1 << 7) == 0;
                let number = if single_byte {
                    first as usize
                } else {
                    if first == 0 {
                        return Err("unnecessary two-byte index");
                    }
                    let next_byte = bytes.next().ok_or("missing second individual index byte")?;
                    (((first & 1 << 7) as usize) << 8) + next_byte as usize
                };

                let idx = if absolute {
                    number as isize
                } else {
                    if single_byte {
                        read_i7(number as u8) as isize
                    } else {
                        read_i15(number as u16) as isize
                    }
                };

                if let Some(last) = selected.last() {
                    if idx <= *last {
                        return Err("individual indices not strictly increasing")?;
                    }
                }
                selected.push(idx);
            }

            if absolute {
                InOutSelector::Absolute(selected.into_iter().map(|i| i as usize).collect())
            } else {
                InOutSelector::Relative(selected)
            }
        };
        Ok(Some((number, selection)))
    }

    pub fn parse(selector: &[u8]) -> Result<TxFields, String> {
        let selector = if selector.is_empty() {
            &TXFS_SPECIAL_TEMPLATE
        } else if selector == &[0x00] {
            &TXFS_SPECIAL_ALL
        } else {
            selector
        };

        let mut bytes = selector.iter().copied();
        let global = bytes.next().expect("checked not empty");

        let (inputs, outputs) = if let Some(inout_fields) = bytes.next() {
            if let Some((nb, sel)) = Self::parse_inout_selector(&mut bytes)? {
                if sel == InOutSelector::None && (inout_fields & TXFS_INPUTS_ALL) != 0 {
                    return Err("no inputs selected, but some field bits set")?;
                }
                if sel != InOutSelector::None && (inout_fields & TXFS_INPUTS_ALL) == 0 {
                    return Err("inputs selected, but no field bits set")?;
                }
                let inputs = Some(InputFields {
                    number: nb,
                    prevouts: (inout_fields & TXFS_INPUTS_PREVOUTS) != 0,
                    sequences: (inout_fields & TXFS_INPUTS_SEQUENCES) != 0,
                    script_sigs: (inout_fields & TXFS_INPUTS_SCRIPTSIGS) != 0,
                    prevout_script_pubkeys: (inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS) != 0,
                    prevout_values: (inout_fields & TXFS_INPUTS_PREV_VALUES) != 0,
                    taproot_annexes: (inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES) != 0,
                    selector: sel,
                });
                let outputs = if let Some((nb, sel)) = Self::parse_inout_selector(&mut bytes)? {
                    if sel == InOutSelector::None && (inout_fields & TXFS_OUTPUTS_ALL) != 0 {
                        return Err("no outputs selected, but some field bits set")?;
                    }
                    if sel != InOutSelector::None && (inout_fields & TXFS_OUTPUTS_ALL) == 0 {
                        return Err("outputs selected, but no field bits set")?;
                    }
                    Some(OutputFields {
                        number: nb,
                        script_pubkeys: (inout_fields & TXFS_OUTPUTS_SCRIPTPUBKEYS) != 0,
                        values: (inout_fields & TXFS_OUTPUTS_VALUES) != 0,
                        selector: sel,
                    })
                } else {
                    if (inout_fields & TXFS_OUTPUTS_ALL) != 0 {
                        return Err("output field bits set but no output selector")?;
                    }
                    None
                };
                (inputs, outputs)
            } else {
                return Err("in/output field byte provided but no selectors")?;
            }
        } else {
            (None, None)
        };

        if bytes.next().is_some() {
            return Err("not all bytes consumed")?;
        }

        Ok(TxFields {
            version: (global & TXFS_VERSION) != 0,
            lock_time: (global & TXFS_LOCKTIME) != 0,
            current_input_idx: (global & TXFS_CURRENT_INPUT_IDX) != 0,
            current_input_spentscript: (global & TXFS_CURRENT_INPUT_SPENTSCRIPT) != 0,
            current_input_control_block: (global & TXFS_CURRENT_INPUT_CONTROL_BLOCK) != 0,
            current_input_last_codeseparator_pos:
                (global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS) != 0,
            inputs, outputs,
        })
    }

    pub fn validate_for(
        &self,
        nb_inputs: usize,
        nb_outputs: usize,
        current_input_idx: u32,
    ) -> Result<(), &'static str> {
        let cur = current_input_idx as isize;
        if let Some(ref inputs) = self.inputs {
            if let InOutSelector::Leading(n) = inputs.selector {
                if n > nb_inputs {
                    return Err("too many leading inputs");
                }
            }
            if let InOutSelector::Absolute(ref s) = inputs.selector {
                if *s.last().unwrap() > nb_inputs {
                    return Err("individual input selected out of range");
                }
            }
            if let InOutSelector::Relative(ref s) = inputs.selector {
                if cur + s.first().unwrap() < 0 || cur + s.last().unwrap() >= nb_inputs as isize {
                    return Err("relative individual input selected out of range");
                }
            }
        }
        if let Some(ref outputs) = self.outputs {
            if let InOutSelector::Leading(n) = outputs.selector {
                if n > nb_outputs {
                    return Err("too many leading outputs");
                }
            }
            if let InOutSelector::Absolute(ref s) = outputs.selector {
                if *s.last().unwrap() > nb_outputs {
                    return Err("individual output selected out of range");
                }
            }
            if let InOutSelector::Relative(ref s) = outputs.selector {
                if cur + s.first().unwrap() < 0 || cur + s.last().unwrap() >= nb_outputs as isize {
                    return Err("relative individual output selected out of range");
                }
            }
        }
        Ok(())
    }
}

fn offset(relative: &[isize], current_input_idx: usize) -> Result<Vec<usize>, String> {
    relative.iter().map(|i| {
        (current_input_idx as isize).checked_add(*i)
            .ok_or("relative index overflow")?
            .try_into().map_err(|_| "relative index underflow".to_owned())
    }).collect()
}

struct InputsCache {
    scriptsigs: Vec<Option<sha256::Hash>>,
    prev_spks: Vec<Option<sha256::Hash>>,
    annexes: Vec<Option<sha256::Hash>>,
    control_blocks: Vec<Option<sha256::Hash>>,
    spentscripts: Vec<Option<sha256::Hash>>,
}

impl InputsCache {
    fn new(nb_inputs: usize) -> InputsCache {
        InputsCache {
            scriptsigs: Vec::new_default(nb_inputs),
            prev_spks: Vec::new_default(nb_inputs),
            annexes: Vec::new_default(nb_inputs),
            control_blocks: Vec::new_default(nb_inputs),
            spentscripts: Vec::new_default(nb_inputs),
        }
    }

    fn scriptsig(&mut self, idx: usize, tx: &Transaction) -> sha256::Hash {
        *self.scriptsigs[idx].get_or_insert_with(|| {
            if tx.input[idx].script_sig.is_empty() {
                SHA256_EMPTY
            } else {
                sha256::Hash::hash(tx.input[idx].script_sig.as_bytes())
            }
        })
    }

    fn prev_spk(&mut self, idx: usize, prevouts: &[TxOut]) -> sha256::Hash {
        *self.prev_spks[idx].get_or_insert_with(|| {
            sha256::Hash::hash(prevouts[idx].script_pubkey.as_bytes())
        })
    }

    fn annex(&mut self, idx: usize, tx: &Transaction, prevouts: &[TxOut]) -> sha256::Hash {
        *self.annexes[idx].get_or_insert_with(|| {
            if prevouts[idx].script_pubkey.is_p2tr() {
                // NB this will only be called for inputs that are p2tr
                if let Some(annex) = tx.input[idx].witness.taproot_annex() {
                    sha256::Hash::hash(annex)
                } else {
                    SHA256_EMPTY
                }
            } else {
                SHA256_EMPTY
            }
        })
    }

    fn control_block(&mut self, idx: usize, tx: &Transaction) -> sha256::Hash {
        *self.control_blocks[idx].get_or_insert_with(|| {
            // NB this will only be called for inputs that are p2tr
            if let Some(cb) = tx.input[idx].witness.taproot_control_block() {
                sha256::Hash::hash(cb)
            } else {
                SHA256_EMPTY
            }
        })
    }

    fn spentscript(&mut self, idx: usize, tx: &Transaction, prev_script: &Script) -> sha256::Hash {
        // NB this will only be called for inputs that are p2sh, p2wsh or p2tr
        *self.spentscripts[idx].get_or_insert_with(|| {
            if prev_script.is_p2sh() {
                sha256::Hash::hash(tx.input[idx].script_sig.as_bytes())
            } else if prev_script.is_p2wsh() {
                sha256::Hash::hash(tx.input[idx].witness.witness_script().expect("p2wsh").as_bytes())
            } else if prev_script.is_p2tr() {
                if let Some(ts) = tx.input[idx].witness.tapscript() {
                    sha256::Hash::hash(ts.as_bytes())
                } else {
                    SHA256_EMPTY
                }
            } else {
                SHA256_EMPTY
            }
        })
    }
}

struct OutputsCache {
    spks: Vec<Option<sha256::Hash>>,
}

impl OutputsCache {
    fn new(nb_outputs: usize) -> OutputsCache {
        OutputsCache {
            spks: Vec::new_default(nb_outputs),
        }
    }

    fn spk(&mut self, idx: usize, tx: &Transaction) -> sha256::Hash {
        *self.spks[idx].get_or_insert_with(|| {
            sha256::Hash::hash(tx.output[idx].script_pubkey.as_bytes())
        })
    }
}

#[derive(Default)]
struct LeadingInputCache {
    prevouts: Vec<Option<sha256::HashEngine>>,
    sequences: Vec<Option<sha256::HashEngine>>,
    scriptsigs: Vec<Option<sha256::HashEngine>>,
    prev_spks: Vec<Option<sha256::HashEngine>>,
    prev_values: Vec<Option<sha256::HashEngine>>,
    annexes: Vec<Option<sha256::HashEngine>>,
}

#[derive(Default)]
struct LeadingOutputCache {
    spks: Vec<Option<sha256::HashEngine>>,
    values: Vec<Option<sha256::HashEngine>>,
}

struct LeadingCache {
    input: LeadingInputCache,
    output: LeadingOutputCache,
}

impl LeadingCache {
    fn new(nb_inputs: usize, nb_outputs: usize) -> LeadingCache {
        LeadingCache {
            input: LeadingInputCache {
                prevouts: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
                sequences: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
                scriptsigs: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
                prev_spks: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
                prev_values: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
                annexes: Vec::new_default(nb_inputs / LEADING_CACHE_INTERVAL),
            },
            output: LeadingOutputCache {
                spks: Vec::new_default(nb_outputs / LEADING_CACHE_INTERVAL),
                values: Vec::new_default(nb_outputs / LEADING_CACHE_INTERVAL),
            },
        }
    }

    fn calc(
        cache: &mut Vec<Option<sha256::HashEngine>>,
        mut add_item: impl FnMut(&mut sha256::HashEngine, usize),
        nb: usize,
    ) -> sha256::Hash {
        let (mut engine, mut idx) = if let Some(mut cache_idx) = (nb / LEADING_CACHE_INTERVAL).checked_sub(1) {
            loop {
                if let Some(engine) = &cache[cache_idx] {
                    break (engine.clone(), (cache_idx + 1) * LEADING_CACHE_INTERVAL);
                } else {
                    if cache_idx == 0 {
                        break (sha256::Hash::engine(), 0);
                    } else {
                        cache_idx -= 1;
                    }
                }
            }
        } else {
            (sha256::Hash::engine(), 0)
        };

        while idx < nb {
            add_item(&mut engine, idx);
            idx += 1;
            if idx % LEADING_CACHE_INTERVAL == 0 {
                let cache_idx = (idx / LEADING_CACHE_INTERVAL) - 1;
                cache[cache_idx] = Some(engine.clone());
            }
        }

        sha256::Hash::from_engine(engine)
    }

    fn input_prevouts(&mut self, nb: usize, tx: &Transaction) -> sha256::Hash {
        Self::calc(
            &mut self.input.prevouts,
            |e, i| { tx.input[i].previous_output.consensus_encode(e).unwrap(); },
            nb,
        )
    }

    fn input_sequences(&mut self, nb: usize, tx: &Transaction) -> sha256::Hash {
        Self::calc(
            &mut self.input.sequences,
            |e, i| { tx.input[i].sequence.consensus_encode(e).unwrap(); },
            nb,
        )
    }

    fn input_scriptsigs(&mut self, nb: usize, inputs: &mut InputsCache, tx: &Transaction) -> sha256::Hash {
        Self::calc(
            &mut self.input.scriptsigs,
            |e, i| e.input(&inputs.scriptsig(i, tx)[..]),
            nb,
        )
    }

    fn input_prev_spks(&mut self, nb: usize, inputs: &mut InputsCache, prevs: &[TxOut]) -> sha256::Hash {
        Self::calc(
            &mut self.input.prev_spks,
            |e, i| e.input(&inputs.prev_spk(i, prevs)[..]),
            nb,
        )
    }

    fn input_prev_values(&mut self, nb: usize, prevs: &[TxOut]) -> sha256::Hash {
        Self::calc(
            &mut self.input.prev_values,
            |e, i| { prevs[i].value.consensus_encode(e).unwrap(); },
            nb,
        )
    }

    fn input_annexes(
        &mut self,
        nb: usize,
        inputs: &mut InputsCache,
        tx: &Transaction,
        prevs: &[TxOut],
    ) -> sha256::Hash {
        Self::calc(
            &mut self.input.annexes,
            |e, i| e.input(&inputs.annex(i, tx, prevs)[..]),
            nb,
        )
    }

    fn output_spks(&mut self, nb: usize, outputs: &mut OutputsCache, tx: &Transaction) -> sha256::Hash {
        Self::calc(
            &mut self.output.spks,
            |e, i| e.input(&outputs.spk(i, tx)[..]),
            nb,
        )
    }

    fn output_values(&mut self, nb: usize, tx: &Transaction) -> sha256::Hash {
        Self::calc(
            &mut self.output.values,
            |e, i| { tx.output[i].value.consensus_encode(e).unwrap(); },
            nb,
        )
    }
}

#[derive(Default, Clone)]
struct AllInputsCache {
    prevouts: Option<sha256::Hash>,
    sequences: Option<sha256::Hash>,
    scriptsigs: Option<sha256::Hash>,
    prev_spks: Option<sha256::Hash>,
    prev_values: Option<sha256::Hash>,
    annexes: Option<sha256::Hash>,
}

impl AllInputsCache {
    fn prevouts(&mut self, leading: &mut LeadingCache, tx: &Transaction) -> sha256::Hash {
        *self.prevouts.get_or_insert_with(|| {
            leading.input_prevouts(tx.input.len(), tx)
        })
    }

    fn sequences(&mut self, leading: &mut LeadingCache, tx: &Transaction) -> sha256::Hash {
        *self.sequences.get_or_insert_with(|| {
            leading.input_sequences(tx.input.len(), tx)
        })
    }

    fn scriptsigs(
        &mut self, leading: &mut LeadingCache, inputs: &mut InputsCache, tx: &Transaction,
    ) -> sha256::Hash {
        *self.scriptsigs.get_or_insert_with(|| {
            leading.input_scriptsigs(tx.input.len(), inputs, tx)
        })
    }

    fn prev_spks(
        &mut self, leading: &mut LeadingCache, inputs: &mut InputsCache, prevouts: &[TxOut],
    ) -> sha256::Hash {
        *self.prev_spks.get_or_insert_with(|| {
            leading.input_prev_spks(prevouts.len(), inputs, prevouts)
        })
    }

    fn prev_values(&mut self, leading: &mut LeadingCache, prevouts: &[TxOut]) -> sha256::Hash {
        *self.prev_values.get_or_insert_with(|| {
            leading.input_prev_values(prevouts.len(), prevouts)
        })
    }

    fn annexes(
        &mut self,
        leading: &mut LeadingCache,
        inputs: &mut InputsCache,
        tx: &Transaction,
        prevs: &[TxOut],
    ) -> sha256::Hash {
        *self.annexes.get_or_insert_with(|| {
            leading.input_annexes(tx.input.len(), inputs, tx, prevs)
        })
    }
}

#[derive(Default, Clone)]
struct AllOutputsCache {
    spks: Option<sha256::Hash>,
    values: Option<sha256::Hash>,
}

impl AllOutputsCache {
    fn spks(
        &mut self, leading: &mut LeadingCache, outputs: &mut OutputsCache, tx: &Transaction,
    ) -> sha256::Hash {
        *self.spks.get_or_insert_with(|| {
            leading.output_spks(tx.output.len(), outputs, tx)
        })
    }

    fn values(&mut self, leading: &mut LeadingCache, tx: &Transaction) -> sha256::Hash {
        *self.values.get_or_insert_with(|| {
            leading.output_values(tx.output.len(), tx)
        })
    }
}

pub struct TxHashCache<'p, T: Borrow<Transaction>> {
    tx: T,
    prevouts: &'p [TxOut],

    inputs_cache: InputsCache,
    outputs_cache: OutputsCache,
    leading: LeadingCache,
    all_inputs_cache: AllInputsCache,
    all_outputs_cache: AllOutputsCache,
}

impl<'p, T: Borrow<Transaction>> TxHashCache<'p, T> {
    pub fn new(tx: T, prevouts: &[TxOut]) -> Result<TxHashCache<T>, &'static str> {
        let nb_inputs = tx.borrow().input.len();
        let nb_outputs = tx.borrow().output.len();
        if nb_inputs != prevouts.len() {
            return Err("prevouts length doesn't equal tx input length");
        }

        Ok(TxHashCache {
            tx: tx,
            prevouts: prevouts,
            inputs_cache: InputsCache::new(nb_inputs),
            outputs_cache: OutputsCache::new(nb_outputs),
            leading: LeadingCache::new(nb_inputs, nb_outputs),
            all_inputs_cache: AllInputsCache::default(),
            all_outputs_cache: AllOutputsCache::default(),
        })
    }

    pub fn leading_input_prevouts(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_prevouts(nb, self.tx.borrow())
    }

    pub fn leading_input_sequences(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_sequences(nb, self.tx.borrow())
    }

    pub fn leading_input_script_sigs(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_scriptsigs(nb, &mut self.inputs_cache, self.tx.borrow())
    }

    pub fn leading_input_prev_script_pubkeys(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_prev_spks(nb, &mut self.inputs_cache, &self.prevouts)
    }

    pub fn leading_input_prev_values(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_prev_values(nb, &self.prevouts)
    }

    pub fn leading_input_taproot_annexes(&mut self, nb: usize) -> sha256::Hash {
        self.leading.input_annexes(nb, &mut self.inputs_cache, self.tx.borrow(), self.prevouts)
    }

    pub fn leading_output_script_pubkeys(&mut self, nb: usize) -> sha256::Hash {
        self.leading.output_spks(nb, &mut self.outputs_cache, self.tx.borrow())
    }

    pub fn leading_output_values(&mut self, nb: usize) -> sha256::Hash {
        self.leading.output_values(nb, self.tx.borrow())
    }

    pub fn all_inputs_prevouts(&mut self) -> sha256::Hash {
        self.all_inputs_cache.prevouts(&mut self.leading, self.tx.borrow())
    }

    pub fn all_inputs_sequences(&mut self) -> sha256::Hash {
        self.all_inputs_cache.sequences(&mut self.leading, self.tx.borrow())
    }

    pub fn all_inputs_script_sigs(&mut self) -> sha256::Hash {
        self.all_inputs_cache.scriptsigs(
            &mut self.leading, &mut self.inputs_cache, self.tx.borrow(),
        )
    }

    pub fn all_inputs_prev_script_pubkeys(&mut self) -> sha256::Hash {
        self.all_inputs_cache.prev_spks(&mut self.leading, &mut self.inputs_cache, self.prevouts)
    }

    pub fn all_inputs_prev_values(&mut self) -> sha256::Hash {
        self.all_inputs_cache.prev_values(&mut self.leading, self.prevouts)
    }

    pub fn all_inputs_taproot_annexes(&mut self) -> sha256::Hash {
        self.all_inputs_cache.annexes(
            &mut self.leading, &mut self.inputs_cache, self.tx.borrow(), self.prevouts,
        )
    }

    pub fn all_outputs_script_pubkeys(&mut self) -> sha256::Hash {
        self.all_outputs_cache.spks(&mut self.leading, &mut self.outputs_cache, self.tx.borrow())
    }

    pub fn all_outputs_values(&mut self) -> sha256::Hash {
        self.all_outputs_cache.values(&mut self.leading, self.tx.borrow())
    }

    pub fn selected_input_prevouts(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            self.tx.borrow().input[*i].previous_output.consensus_encode(&mut engine).unwrap();
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_input_sequences(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            self.tx.borrow().input[*i].sequence.consensus_encode(&mut engine).unwrap();
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_input_script_sigs(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            engine.input(&self.inputs_cache.scriptsig(*i, self.tx.borrow())[..]);
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_input_prev_script_pubkeys(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            engine.input(&self.inputs_cache.prev_spk(*i, self.prevouts)[..]);
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_input_prev_values(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            self.prevouts[*i].value.consensus_encode(&mut engine).unwrap();
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_input_taproot_annexes(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            engine.input(&self.inputs_cache.annex(*i, self.tx.borrow(), self.prevouts)[..]);
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_output_script_pubkeys(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            engine.input(&self.outputs_cache.spk(*i, self.tx.borrow())[..]);
        }
        sha256::Hash::from_engine(engine)
    }

    pub fn selected_output_values(&mut self, select: &[usize]) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        for i in select {
            self.tx.borrow().output[*i].value.consensus_encode(&mut engine).unwrap();
        }
        sha256::Hash::from_engine(engine)
    }


    pub fn calculate_txhash(
        &mut self,
        txfs: &[u8],
        current_input_idx: u32,
        current_input_last_codeseparator_pos: Option<u32>,
    ) -> Result<sha256::Hash, String> {
        let txfs = if txfs.is_empty() {
            &TXFS_SPECIAL_TEMPLATE
        } else if txfs.len() == 1 && txfs[0] == 0x00 {
            &TXFS_SPECIAL_ALL
        } else {
            txfs
        };

        let fields = TxFields::parse(txfs)?;
        fields.validate_for(
            self.tx.borrow().input.len(), self.tx.borrow().output.len(), current_input_idx,
        )?;

        let mut engine = sha256::Hash::engine();

        if txfs[0] & TXFS_CONTROL != 0 {
            engine.input(txfs);
        }

        if fields.version {
            self.tx.borrow().version.consensus_encode(&mut engine).unwrap();
        }

        if fields.lock_time {
            self.tx.borrow().lock_time.consensus_encode(&mut engine).unwrap();
        }

        if fields.current_input_idx {
            (current_input_idx as u32).consensus_encode(&mut engine).unwrap();
        }

        let cur = current_input_idx as usize;
        if fields.current_input_spentscript {
            let prev = &self.prevouts[cur].script_pubkey;
            let ss_hash = self.inputs_cache.spentscript(cur, self.tx.borrow(), prev);
            engine.input(&ss_hash[..]);
        }

        if fields.current_input_control_block {
            let cb_hash = if self.prevouts[cur].script_pubkey.is_p2tr() {
                self.inputs_cache.control_block(cur, self.tx.borrow())
            } else {
                SHA256_EMPTY
            };
            engine.input(&cb_hash[..]);
        }

        if fields.current_input_last_codeseparator_pos {
            let pos = current_input_last_codeseparator_pos.unwrap_or(u32::MAX);
            (pos as u32).consensus_encode(&mut engine).unwrap();
        }

        if let Some(inputs) = fields.inputs {
            if inputs.number {
                (self.tx.borrow().input.len() as u32).consensus_encode(&mut engine).unwrap();
            }

            if !inputs.selector.is_none() {
                if inputs.prevouts {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_prevouts(),
                        InOutSelector::Leading(n) => self.leading_input_prevouts(n),
                        InOutSelector::Current => self.selected_input_prevouts(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_input_prevouts(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_prevouts(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }

                if inputs.sequences {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_sequences(),
                        InOutSelector::Leading(n) => self.leading_input_sequences(n),
                        InOutSelector::Current => self.selected_input_sequences(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_input_sequences(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_sequences(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }

                if inputs.script_sigs {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_script_sigs(),
                        InOutSelector::Leading(n) => self.leading_input_script_sigs(n),
                        InOutSelector::Current => self.selected_input_script_sigs(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_input_script_sigs(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_script_sigs(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }

                if inputs.prevout_script_pubkeys {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_prev_script_pubkeys(),
                        InOutSelector::Leading(n) => self.leading_input_prev_script_pubkeys(n),
                        InOutSelector::Current => self.selected_input_prev_script_pubkeys(&[cur]),
                        InOutSelector::Absolute(ref s) => {
                            self.selected_input_prev_script_pubkeys(s)
                        },
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_prev_script_pubkeys(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }

                if inputs.prevout_values {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_prev_values(),
                        InOutSelector::Leading(n) => self.leading_input_prev_values(n),
                        InOutSelector::Current => self.selected_input_prev_values(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_input_prev_values(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_prev_values(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }

                if inputs.taproot_annexes {
                    let hash = match inputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_inputs_taproot_annexes(),
                        InOutSelector::Leading(n) => self.leading_input_taproot_annexes(n),
                        InOutSelector::Current => self.selected_input_taproot_annexes(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_input_taproot_annexes(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_input_taproot_annexes(&offset(s, cur)?)
                        },
                    };
                    engine.input(&hash[..]);
                }
            }
        }

        if let Some(outputs) = fields.outputs {
            if outputs.number {
                (self.tx.borrow().output.len() as u32).consensus_encode(&mut engine).unwrap();
            }

            if !outputs.selector.is_none() {
                if outputs.script_pubkeys {
                    let hash = match outputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_outputs_script_pubkeys(),
                        InOutSelector::Leading(n) => self.leading_output_script_pubkeys(n),
                        InOutSelector::Current => self.selected_output_script_pubkeys(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_output_script_pubkeys(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_output_script_pubkeys(&offset(s, cur)?)
                        },
                    };
                    hash.consensus_encode(&mut engine).unwrap();
                }

                if outputs.values {
                    let hash = match outputs.selector {
                        InOutSelector::None => unreachable!(),
                        InOutSelector::All => self.all_outputs_values(),
                        InOutSelector::Leading(n) => self.leading_output_values(n),
                        InOutSelector::Current => self.selected_output_values(&[cur]),
                        InOutSelector::Absolute(ref s) => self.selected_output_values(s),
                        InOutSelector::Relative(ref s) => {
                            self.selected_output_values(&offset(s, cur)?)
                        },
                    };
                    hash.consensus_encode(&mut engine).unwrap();
                }
            }
        }

        Ok(sha256::Hash::from_engine(engine))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex::DisplayHex;

    #[test]
    fn test_empty() {
        assert_eq!(SHA256_EMPTY.to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_txfs_templates() {
        assert_eq!("bff6bfbf", TXFS_SPECIAL_TEMPLATE.as_hex().to_string());
        assert_eq!("bfffbfbf", TXFS_SPECIAL_ALL.as_hex().to_string());
    }

    #[cfg(feature = "serde")]
    mod test_vectors {
        use super::*;
        use std::io;

        #[derive(Debug)]
        struct TestCase {
            tx: Transaction,
            prevs: Vec<TxOut>,
            vectors: Vec<TestVector>
        }

        #[derive(Debug)]
        struct TestVector {
            id: String,
            txfs: Vec<u8>,
            input: usize,
            codeseparator: Option<u32>,
            txhash: sha256::Hash,
        }

        //TODO(stevenroose) remove this method when it lands
        //https://github.com/rust-bitcoin/rust-bitcoin/pull/2039/files
        fn deserialize_hex<T: crate::consensus::Decodable>(hex: &str) -> T {
            let mut iter = io::BufReader::new(hex::HexToBytesIter::new(hex).unwrap());
            let ret = crate::consensus::Decodable::consensus_decode_from_finite_reader(&mut iter).unwrap();
            assert!(iter.buffer().is_empty() && iter.into_inner().next().is_none());
            ret
        }

        fn read_vector_file() -> Vec<TestCase> {
            use serde::Deserialize;
            use hex::FromHex;

            #[derive(Deserialize)]
            #[serde(crate = "actual_serde")]
            struct SerializedTestCase {
                tx: String,
                prevs: Vec<String>,
                vectors: Vec<SerializedTestVector>
            }

            #[derive(Deserialize)]
            #[serde(crate = "actual_serde")]
            struct SerializedTestVector {
                id: String,
                txfs: String,
                input: usize,
                codeseparator: Option<u32>,
                txhash: sha256::Hash,
            }

            let json_str = include_str!("../../../tests/data/txhash_vectors.json");
            let json = serde_json::from_str::<Vec<SerializedTestCase>>(json_str).unwrap();
            json.into_iter().map(|c| TestCase {
                tx: deserialize_hex(&c.tx),
                prevs: c.prevs.into_iter().map(|p| deserialize_hex(&p)).collect(),
                vectors: c.vectors.into_iter().map(|v| TestVector {
                    id: v.id,
                    txfs: FromHex::from_hex(&v.txfs).unwrap(),
                    input: v.input,
                    codeseparator: v.codeseparator,
                    txhash: v.txhash,
                }).collect(),
            }).collect()
        }

        #[test]
        fn test_vectors() {
            for case in read_vector_file() {
                let mut persistent_cache = TxHashCache::new(&case.tx, &case.prevs).unwrap();
                for v in case.vectors {
                    println!("vector {}", v.id);
                    if !v.txfs.is_empty() && v.txfs != &[0x00] {
                        let fields = TxFields::parse(&v.txfs).expect("failed to parse fields");
                        fields.validate_for(
                            case.tx.input.len(), case.tx.output.len(), v.input as u32,
                        ).expect("txfields invalid");
                        println!("fields: {:#?}", fields);
                    }

                    let mut new_cache = TxHashCache::new(&case.tx, &case.prevs).unwrap();
                    assert_eq!(
                        v.txhash,
                        new_cache.calculate_txhash(&v.txfs, v.input as u32, v.codeseparator).unwrap(),
                    );
                    assert_eq!(
                        v.txhash,
                        persistent_cache.calculate_txhash(&v.txfs, v.input as u32, v.codeseparator).unwrap(),
                    );
                }
            }
        }
    }
}
