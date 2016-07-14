// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::default::Default;
use std::{error, fmt, ops};
use serialize::hex::ToHex;

use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use secp256k1::{self, Secp256k1};
use secp256k1::key::PublicKey;
use serde;

use blockdata::opcodes;
use blockdata::transaction::{Transaction, TxIn};
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::serialize::{SimpleDecoder, SimpleEncoder, serialize};
use util::hash::Sha256dHash;
use util::misc::script_find_and_remove;

#[derive(Clone, PartialEq, Eq, Hash)]
/// A Bitcoin script
pub struct Script(Box<[u8]>);

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut index = 0;

        try!(f.write_str("Script("));
        while index < self.0.len() {
            let opcode = opcodes::All::from(self.0[index]);

            let data_len = if let opcodes::Class::PushBytes(n) = opcode.classify() {
                n as usize
            } else {
                match opcode {
                    opcodes::All::OP_PUSHDATA1 => {
                        if self.0.len() < index + 1 {
                            try!(f.write_str("<unexpected end>"));
                            break;
                        }
                        match read_uint(&self.0[index..], 1) {
                            Ok(n) => { index += 1; n as usize }
                            Err(_) => { try!(f.write_str("<bad length>")); break; }
                        }
                    }
                    opcodes::All::OP_PUSHDATA2 => {
                        if self.0.len() < index + 2 {
                            try!(f.write_str("<unexpected end>"));
                            break;
                        }
                        match read_uint(&self.0[index..], 2) {
                            Ok(n) => { index += 2; n as usize }
                            Err(_) => { try!(f.write_str("<bad length>")); break; }
                        }
                    }
                    opcodes::All::OP_PUSHDATA4 => {
                        if self.0.len() < index + 4 {
                            try!(f.write_str("<unexpected end>"));
                            break;
                        }
                        match read_uint(&self.0[index..], 4) {
                            Ok(n) => { index += 4; n as usize }
                            Err(_) => { try!(f.write_str("<bad length>")); break; }
                        }
                    }
                    _ => 0
                }
            };

            if index > 0 { try!(f.write_str(" ")); }
            // Write the opcode
            if opcode == opcodes::All::OP_PUSHBYTES_0 {
                try!(f.write_str("OP_0"));
            } else {
                try!(write!(f, "{:?}", opcode));
            }
            index += 1;
            // Write any pushdata
            if data_len > 0 {
                try!(f.write_str(" "));
                if index + data_len < self.0.len() {
                    for ch in &self.0[index..index + data_len] {
                            try!(write!(f, "{:02x}", ch));
                    }
                    index += data_len;
                } else {
                    try!(f.write_str("<push past end>"));
                    break;
                }
            }
        }
        f.write_str(")")
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
            try!(write!(f, "{:02x}", ch));
        }
        Ok(())
    }
}

impl fmt::UpperHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
            try!(write!(f, "{:02X}", ch));
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// An object which can be used to construct a script piece by piece
pub struct Builder(Vec<u8>);
display_from_debug!(Builder);

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Error {
    /// Tried to set a boolean to both values, but neither worked
    AnalyzeNeitherBoolWorks,
    /// Tried to set a boolean to the given value, but it already
    /// had the other value
    AnalyzeSetBoolMismatch(bool),
    /// Validation of an element failed
    AnalyzeValidateFailed,
    /// OP_CHECKSIG was called with a bad public key
    BadPublicKey,
    /// OP_CHECKSIG was called with a bad signature
    BadSignature,
    /// An ECDSA error
    Ecdsa(secp256k1::Error),
    /// An OP_ELSE happened while not in an OP_IF tree
    ElseWithoutIf,
    /// An OP_ENDIF happened while not in an OP_IF tree
    EndifWithoutIf,
    /// An OP_EQUALVERIFY failed (expected, gotten)
    EqualVerifyFailed(String, String),
    /// An OP_IF happened with an empty stack
    IfEmptyStack,
    /// An illegal opcode appeared in the script (does not need to be executed)
    IllegalOpcode,
    /// The interpreter overflowed its stack. This never happens for
    /// script evaluation, only non-consensus analysis passes.
    InterpreterStackOverflow,
    /// Some opcode expected a parameter, but it was missing or truncated
    EarlyEndOfScript,
    /// An OP_RETURN or synonym was executed
    ExecutedReturn,
    /// A multisig tx with negative or too many keys
    MultisigBadKeyCount(isize),
    /// A multisig tx with negative or too many signatures
    MultisigBadSigCount(isize),
    /// Used OP_PICK with a negative index
    NegativePick,
    /// Used OP_ROLL with a negative index
    NegativeRoll,
    /// Tried to execute a signature operation but no transaction context was provided
    NoTransaction,
    /// An OP_NUMEQUALVERIFY failed (expected, gotten)
    NumEqualVerifyFailed(i64, i64),
    /// Tried to read an array off the stack as a number when it was more than 4 bytes
    NumericOverflow,
    /// Some stack operation was done with an empty stack
    PopEmptyStack,
    /// Analysis was unable to determine script input
    Unanalyzable,
    /// Analysis showed script cannot be satisfied
    Unsatisfiable,
    /// An OP_VERIFY happened with an empty stack
    VerifyEmptyStack,
    /// An OP_VERIFY happened with zero on the stack
    VerifyFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Ecdsa(ref e) => fmt::Display::fmt(e, f),
            Error::EqualVerifyFailed(ref exp, ref got) => write!(f, "OP_EQUALVERIFY failed; {} != {}", exp, got),
            Error::MultisigBadKeyCount(n) => write!(f, "bad number {} of keys for multisignature", n),
            Error::MultisigBadSigCount(n) => write!(f, "bad number {} of signatures for multisignature", n),
            Error::NumEqualVerifyFailed(exp, got) => write!(f, "OP_NUMEQUALVERIFY failed; {} != {}", exp, got),
            _ => f.write_str(error::Error::description(self))
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Ecdsa(ref e) => Some(e),
            _ => None
        }
    }

    fn description(&self) -> &'static str {
        match *self {
            Error::AnalyzeNeitherBoolWorks => "analyzer: switch on boolean but neither side is satisfiable",
            Error::AnalyzeSetBoolMismatch(_) => "analyzer: conflicting requirements on boolean",
            Error::AnalyzeValidateFailed => "analyzer: conflicting requirements on stack element",
            Error::BadPublicKey => "analyzer: CHECKSIG called with bad public key",
            Error::BadSignature => "analyzer: CHECKSIG called with bad signature",
            Error::Ecdsa(_) => "libsecp error",
            Error::ElseWithoutIf => "unexpected OP_ELSE",
            Error::EndifWithoutIf => "unexpected OP_ENDIF",
            Error::EqualVerifyFailed(_, _) => "OP_EQUALVERIFY failed",
            Error::IfEmptyStack => "OP_IF called with nothing on the stack",
            Error::IllegalOpcode => "an illegal opcode exists in the script",
            Error::InterpreterStackOverflow => "analyzer: stack overflow",
            Error::EarlyEndOfScript => "unexpected end of script",
            Error::ExecutedReturn => "OP_RETURN or equivalent was executed",
            Error::MultisigBadKeyCount(_) => "bad key count for multisignature",
            Error::MultisigBadSigCount(_) => "bad signature count for multisignature",
            Error::NegativePick => "OP_PICK called with negative index",
            Error::NegativeRoll => "OP_ROLL called with negative index",
            Error::NoTransaction => "OP_CHECKSIG evaluated outside of transaction environment",
            Error::NumEqualVerifyFailed(_, _) => "OP_NUMEQUALVERIFY failed",
            Error::NumericOverflow => "numeric overflow (number on stack larger than 4 bytes)",
            Error::PopEmptyStack => "stack was empty but script expected otherwise",
            Error::Unanalyzable => "analyzer: unable to determine script satisfiability",
            Error::Unsatisfiable => "analyzer: script is unsatisfiable",
            Error::VerifyEmptyStack => "OP_VERIFY called on an empty stack",
            Error::VerifyFailed => "OP_VERIFY called with false on top of stack"
        }
    }
}

/// A rule for validating an abstract stack element
pub struct Validator {
    /// List of other elements to pass to both `check` and `update`
    args: Vec<usize>,
    /// Function which confirms that the current value is consistent with
    /// the stack state, returning `false` if not.
    check: fn(&AbstractStackElem, &[usize]) -> bool,
    /// Function which updates the current stack based on the element's
    /// value, if it has a value, otherwise updates the element's value
    /// based on the current stack, if possible. Returns `false` if it
    /// is forced to do something inconsistent.
    update: fn(&mut AbstractStackElem, &[usize]) -> Result<(), Error>
}

impl Clone for Validator {
    fn clone(&self) -> Validator {
        Validator {
            args: self.args.clone(),
            check: self.check,
            update: self.update
        }
    }
}

// Validators
mod check {
    use super::AbstractStackElem;

    pub fn op_size(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let other = unsafe { elem.lookup(others[0]) };
        elem.num_hi() >= other.len_lo() as i64 &&
        elem.num_lo() <= other.len_hi() as i64
    }

    pub fn op_equal(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        match elem.bool_value() {
            None => true,
            Some(false) => {
                (one.num_value().is_none() || two.num_value().is_none() ||
                 one.num_value().unwrap() != two.num_value().unwrap()) &&
                (one.bool_value() != Some(false) || two.bool_value() != Some(false)) &&
                (one.raw_value().is_none() || two.raw_value().is_none() ||
                 one.raw_value().unwrap() != two.raw_value().unwrap())
            }
            Some(true) => {
                one.len_lo() <= two.len_hi() &&
                one.len_hi() >= two.len_lo() &&
                one.num_lo() <= two.num_hi() &&
                one.num_hi() >= two.num_lo() &&
                (one.bool_value().is_none() || two.bool_value().is_none() ||
                 one.bool_value().unwrap() == two.bool_value().unwrap()) &&
                (one.raw_value().is_none() || two.raw_value().is_none() ||
                 one.raw_value().unwrap() == two.raw_value().unwrap())
            }
        }
    }

    pub fn op_not(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        if !one.may_be_numeric() {
            return false;
        }

        match elem.bool_value() {
            None => true,
            Some(false) => one.num_hi() != 0 || one.num_lo() != 0,
            Some(true) => one.num_hi() >= 0 && one.num_lo() <= 0
        }
    }

    pub fn op_0notequal(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        if !one.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(false) => one.num_hi() >= 0 && one.num_lo() <= 0,
            Some(true) => one.num_hi() != 0 || one.num_lo() != 0
        }
    }

    pub fn op_numequal(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(false) => {
                (one.num_value().is_none() || two.num_value().is_none() ||
                 one.num_value().unwrap() != two.num_value().unwrap()) &&
                (one.bool_value().is_none() || two.bool_value().is_none() ||
                 one.bool_value().unwrap() != two.bool_value().unwrap())
            }
            Some(true) => {
                one.num_lo() <= two.num_hi() &&
                one.num_hi() >= two.num_lo() &&
                (one.num_value().is_none() || two.num_value().is_none() ||
                 one.num_value().unwrap() == two.num_value().unwrap()) &&
                (one.bool_value().is_none() || two.bool_value().is_none() ||
                 one.bool_value().unwrap() == two.bool_value().unwrap())
            }
        }
    }

    pub fn op_numnotequal(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(false) => one.may_be_lt(two) || one.may_be_gt(two),
            Some(true) => one.may_be_lteq(two) && one.may_be_gteq(two)
        }
    }

    pub fn op_numlt(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(true) => one.may_be_lt(two),
            Some(false) => one.may_be_gteq(two),
        }
    }

    pub fn op_numgt(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(true) => one.may_be_gt(two),
            Some(false) => one.may_be_lteq(two)
        }
    }

    pub fn op_numlteq(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(false) => one.may_be_gt(two),
            Some(true) => one.may_be_lteq(two)
        }
    }

    pub fn op_numgteq(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        if !one.may_be_numeric() { return false; }
        if !two.may_be_numeric() { return false; }
        match elem.bool_value() {
            None => true,
            Some(true) => one.may_be_gteq(two),
            Some(false) => one.may_be_lt(two)
        }
    }

    pub fn op_ripemd160(elem: &AbstractStackElem, _: &[usize]) -> bool {
        elem.may_be_hash160()
    }

    pub fn op_sha1(elem: &AbstractStackElem, _: &[usize]) -> bool {
        elem.may_be_hash160()
    }

    pub fn op_hash160(elem: &AbstractStackElem, _: &[usize]) -> bool {
        elem.may_be_hash160()
    }
    
    pub fn op_sha256(elem: &AbstractStackElem, _: &[usize]) -> bool {
        elem.may_be_hash256()
    }

    pub fn op_hash256(elem: &AbstractStackElem, _: &[usize]) -> bool {
        elem.may_be_hash256()
    }

    pub fn op_checksig(elem: &AbstractStackElem, others: &[usize]) -> bool {
        let one = unsafe { elem.lookup(others[0]) };
        let two = unsafe { elem.lookup(others[1]) };
        match elem.bool_value() {
            None => true,
            Some(false) => true,
            Some(true) => one.may_be_signature() && two.may_be_pubkey()
        }
    }

}

mod update {
    use super::{AbstractStackElem, Error};
    use crypto::digest::Digest;
    use crypto::ripemd160::Ripemd160;
    use crypto::sha1::Sha1;
    use crypto::sha2::Sha256;

    pub fn op_size(elem: &mut AbstractStackElem, others: &[usize])
              -> Result<(), Error> {
        let (lo, hi) = {
            let one = unsafe { elem.lookup(others[0]) };
            (one.len_lo() as i64, one.len_hi() as i64)
        };
        try!(elem.set_numeric());
        try!(elem.set_num_lo(lo));
        elem.set_num_hi(hi)
    }

    fn boolean(elem: &mut AbstractStackElem) -> Result<(), Error> {
        // Test boolean values
        elem.bool_val = Some(true);
        let true_works = elem.validate();
        elem.bool_val = Some(false);
        let false_works = elem.validate();
        elem.bool_val = None;
        // Update according to what worked
        match (true_works, false_works) {
            (true,    true)    => Ok(()),
            (false, false) => Err(Error::AnalyzeNeitherBoolWorks),
            (true,    false) => elem.set_bool_value(true),
            (false, true)    => elem.set_bool_value(false)
        }
    }

    pub fn op_equal(elem: &mut AbstractStackElem, others: &[usize])
               -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                // Booleans are the only thing we can do something useful with re "not equal"
                match (one.bool_value(), two.bool_value()) {
                    (None, None) => Ok(()),
                    (None, Some(x)) => one.set_bool_value(!x),
                    (Some(x), None) => two.set_bool_value(!x),
                    (Some(x), Some(y)) if x == y => Err(Error::Unsatisfiable),
                    (Some(_), Some(_)) => Ok(())
                }
            }
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                // Equalize numeric bounds
                try!(one.set_num_lo(two.num_lo()));
                try!(one.set_num_hi(two.num_hi()));
                try!(two.set_num_lo(one.num_lo()));
                try!(two.set_num_hi(one.num_hi()));
                // Equalize boolean values
                match (one.bool_value(), two.bool_value()) {
                    (None, None) => {},
                    (None, Some(x)) => try!(one.set_bool_value(x)),
                    (Some(x), None) => try!(two.set_bool_value(x)),
                    (Some(x), Some(y)) if x == y => {},
                    (Some(_), Some(_)) => { return Err(Error::Unsatisfiable); }
                }
                // Equalize full values
                match (one.raw_value().map(|r| r.to_vec()),
                             two.raw_value().map(|r| r.to_vec())) {
                    (None, None) => {},
                    (None, Some(x)) => try!(one.set_value(&x)),
                    (Some(x), None) => try!(two.set_value(&x)),
                    (Some(x), Some(y)) => { if x != y { return Err(Error::Unsatisfiable); } }
                }
                Ok(())
            }
        }
    }

    pub fn op_not(elem: &mut AbstractStackElem, others: &[usize])
             -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                try!(one.set_numeric());
                match one.bool_value() {
                    None => one.set_bool_value(true),
                    Some(true) => Ok(()),
                    Some(false) => Err(Error::Unsatisfiable)
                }
            }
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                try!(one.set_numeric());
                match one.bool_value() {
                    None => one.set_num_value(0),
                    Some(true) => Err(Error::Unsatisfiable),
                    Some(false) => Ok(())
                }
            }
        }
    }

    pub fn op_0notequal(elem: &mut AbstractStackElem, others: &[usize])
                   -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                try!(one.set_numeric());
                match one.bool_value() {
                    None => one.set_num_value(0),
                    Some(true) => Err(Error::Unsatisfiable),
                    Some(false) => Ok(())
                }
            }
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                try!(one.set_numeric());
                match one.bool_value() {
                    None => one.set_bool_value(true),
                    Some(true) => Ok(()),
                    Some(false) => Err(Error::Unsatisfiable)
                }
            }
        }
    }

    pub fn op_numequal(elem: &mut AbstractStackElem, others: &[usize])
                  -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => {
                // todo: find a way to force the numbers to be nonequal
                Ok(())
            }
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
                try!(one.set_num_lo(two.num_lo()));
                try!(one.set_num_hi(two.num_hi()));
                try!(two.set_num_lo(one.num_lo()));
                two.set_num_hi(one.num_hi())
            }
        }
    }

    pub fn op_numnotequal(elem: &mut AbstractStackElem, others: &[usize])
                     -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
                try!(one.set_num_lo(two.num_lo()));
                try!(one.set_num_hi(two.num_hi()));
                try!(two.set_num_lo(one.num_lo()));
                two.set_num_hi(one.num_hi())
            }
            Some(true) => {
                // todo: find a way to force the numbers to be nonequal
                Ok(())
            }
        }
    }

    pub fn op_numlt(elem: &mut AbstractStackElem, others: &[usize])
               -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_hi(two.num_hi() - 1));
                two.set_num_lo(one.num_lo() + 1)
            }
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_lo(two.num_lo()));
                two.set_num_hi(one.num_hi())
            }
        }
    }

    pub fn op_numgt(elem: &mut AbstractStackElem, others: &[usize])
               -> Result<(), Error> {
        match elem.bool_value() {
            None => try!(boolean(elem)),
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_lo(two.num_lo() + 1));
                try!(two.set_num_hi(one.num_hi() - 1));
            }
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_hi(two.num_hi()));
                try!(two.set_num_lo(one.num_lo()));
            }
        }
        Ok(())
    }

    pub fn op_numlteq(elem: &mut AbstractStackElem, others: &[usize])
                 -> Result<(), Error> {
        match elem.bool_value() {
            None => try!(boolean(elem)),
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_hi(two.num_hi()));
                try!(two.set_num_lo(one.num_lo()));
            }
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_lo(two.num_lo() + 1));
                try!(two.set_num_hi(one.num_hi() - 1));
            }
        }
        Ok(())
    }

    pub fn op_numgteq(elem: &mut AbstractStackElem, others: &[usize])
                 -> Result<(), Error> {
        match elem.bool_value() {
            None => try!(boolean(elem)),
            Some(true) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_lo(two.num_lo()));
                try!(two.set_num_hi(one.num_hi()));
            }
            Some(false) => {
                let one = unsafe { elem.lookup_mut(others[0]) };
                let two = unsafe { elem.lookup_mut(others[1]) };
                try!(one.set_numeric());
                try!(two.set_numeric());
    
                try!(one.set_num_hi(two.num_hi() - 1));
                try!(two.set_num_lo(one.num_lo() + 1));
            }
        }
        Ok(())
    }

    pub fn op_ripemd160(elem: &mut AbstractStackElem, others: &[usize])
                   -> Result<(), Error> {
        try!(elem.set_len_lo(20));
        try!(elem.set_len_hi(20));
    
        let hash = match unsafe { elem.lookup(others[0]) }.raw_value() {
            None => None,
            Some(x) => {
                let mut out = [0; 20];
                let mut engine = Ripemd160::new();
                engine.input(x);
                engine.result(&mut out);
                Some(out)
            }
        };

        match hash {
            None => Ok(()),
            Some(x) => elem.set_value(&x)
        }
    }

    pub fn op_sha1(elem: &mut AbstractStackElem, others: &[usize])
              -> Result<(), Error> {
        try!(elem.set_len_lo(20));
        try!(elem.set_len_hi(20));
    
        let hash = match unsafe { elem.lookup(others[0]) }.raw_value() {
            None => None,
            Some(x) => {
                let mut out = [0; 20];
                let mut engine = Sha1::new();
                engine.input(x);
                engine.result(&mut out);
                Some(out)
            }
        };

        match hash {
            None => Ok(()),
            Some(x) => elem.set_value(&x)
        }
    }

    pub fn op_hash160(elem: &mut AbstractStackElem, others: &[usize])
                 -> Result<(), Error> {
        try!(elem.set_len_lo(20));
        try!(elem.set_len_hi(20));
    
        let hash = match unsafe { elem.lookup(others[0]) }.raw_value() {
            None => None,
            Some(x) => {
                let mut out1 = [0; 32];
                let mut out2 = [0; 20];
                let mut engine = Sha256::new();
                engine.input(x);
                engine.result(&mut out1);
                let mut engine = Ripemd160::new();
                engine.input(&out1);
                engine.result(&mut out2);
                Some(out2)
            }
        };

        match hash {
            None => Ok(()),
            Some(x) => elem.set_value(&x)
        }
    }

    pub fn op_sha256(elem: &mut AbstractStackElem, others: &[usize])
                -> Result<(), Error> {
        try!(elem.set_len_lo(32));
        try!(elem.set_len_hi(32));

        let hash = match unsafe { elem.lookup(others[0]) }.raw_value() {
            None => None,
            Some(x) => {
                let mut out = [0; 32];
                let mut engine = Sha256::new();
                engine.input(x);
                engine.result(&mut out);
                Some(out)
            }
        };

        match hash {
            None => Ok(()),
            Some(x) => elem.set_value(&x)
        }
    }

    pub fn op_hash256(elem: &mut AbstractStackElem, others: &[usize])
                 -> Result<(), Error> {
        try!(elem.set_len_lo(32));
        try!(elem.set_len_hi(32));
    
        let hash = match unsafe { elem.lookup(others[0]) }.raw_value() {
            None => None,
            Some(x) => {
                let mut out = [0; 32];
                let mut engine = Sha256::new();
                engine.input(x);
                engine.result(&mut out);
                let mut engine = Sha256::new();
                engine.input(&out);
                engine.result(&mut out);
                Some(out)
            }
        };

        match hash {
            None => Ok(()),
            Some(x) => elem.set_value(&x)
        }
    }

    pub fn op_checksig(elem: &mut AbstractStackElem, others: &[usize])
                  -> Result<(), Error> {
        match elem.bool_value() {
            None => boolean(elem),
            Some(false) => Ok(()), // nothing we can do to enforce an invalid sig
            Some(true) => {
                let sig = unsafe { elem.lookup_mut(others[0]) };
                let pk    = unsafe { elem.lookup_mut(others[1]) };
    
                // todo add DER encoding enforcement
                try!(pk.set_len_lo(33));
                try!(pk.set_len_hi(65));
                try!(sig.set_len_lo(75));
                sig.set_len_hi(80)
            }
        }
    }
}

/// An abstract element on the stack, used to describe a satisfying
/// script input
#[derive(Clone)]
pub struct AbstractStackElem {
    /// The raw data, if known
    raw: Option<Vec<u8>>,
    /// Boolean value, if forced
    bool_val: Option<bool>,
    /// Lower bound when read as number
    num_lo: i64,
    /// Upper bound when read as number
    num_hi: i64,
    /// Length lower bound
    len_lo: usize,
    /// Length upper bound
    len_hi: usize,
    /// Relations this must satisfy
    validators: Vec<Validator>,
    /// Index of the element in its stack allocator
    alloc_index: Option<usize>
}

impl AbstractStackElem {
    /// Create a new exact integer
    pub fn new_num(n: i64) -> AbstractStackElem {
        let raw = build_scriptint(n);
        AbstractStackElem {
            num_lo: n,
            num_hi: n,
            len_lo: raw.len(),
            len_hi: raw.len(),
            raw: Some(raw),
            bool_val: Some(n != 0),
            validators: vec![],
            alloc_index: None
        }
    }

    /// Create a new exact boolean
    pub fn new_bool(b: bool) -> AbstractStackElem {
        AbstractStackElem::new_num(if b { 1 } else { 0 })
    }

    /// Create a new exact data
    pub fn new_raw(data: &[u8]) -> AbstractStackElem {
        let n = read_scriptint(data);
        AbstractStackElem {
            num_lo: match n { Ok(n) => n, Err(_) => -(1 << 31) },
            num_hi: match n { Ok(n) => n, Err(_) => 1 << 31 },
            len_lo: data.len(),
            len_hi: data.len(),
            bool_val: Some(read_scriptbool(data)),
            raw: Some(data.to_vec()),
            validators: vec![],
            alloc_index: None
        }
    }

    /// Create a new unknown element
    pub fn new_unknown() -> AbstractStackElem {
        AbstractStackElem {
            num_lo: -(1 << 31),
            num_hi: 1 << 31,
            len_lo: 0,
            len_hi: 1 << 20,    // blocksize limit
            bool_val: None,
            raw: None,
            validators: vec![],
            alloc_index: None
        }
    }

    /// Looks up another stack item by index
    unsafe fn lookup(&self, idx: usize) -> &AbstractStackElem {
        let mypos = self as *const _;
        let myidx = self.alloc_index.unwrap() as isize;
        &*mypos.offset(idx as isize - myidx)
    }

    /// Looks up another stack item by index
    unsafe fn lookup_mut(&self, idx: usize) -> &mut AbstractStackElem {
        let mypos = self as *const _ as *mut _;
        let myidx = self.alloc_index.unwrap() as isize;
        &mut *mypos.offset(idx as isize - myidx)
    }

    /// Retrieve the boolean value of the stack element, if it can be determined
    pub fn bool_value(&self) -> Option<bool> {
        self.bool_val
    }

    /// Retrieves the raw value of the stack element, if it can be determined
    pub fn raw_value(&self) -> Option<&[u8]> {
        self.raw.as_ref().map(|x| &x[..])
    }

    /// Retrieve the upper bound for this element's numeric value.
    /// This can always be determined since there is a fixed upper
    /// bound for all numbers.
    pub fn num_hi(&self) -> i64 {
        self.num_hi
    }

    /// Retrieve the lower bound for this element's numeric value.
    /// This can always be determined since there is a fixed lower
    /// bound for all numbers.
    pub fn num_lo(&self) -> i64 {
        self.num_lo
    }

    /// Retrieve the upper bound for this element's length. This always
    /// exists as a finite value, though the default upper limit is some
    /// impractically large number
    pub fn len_hi(&self) -> usize {
        self.len_hi
    }

    /// Retrieve the lower bound for this element's length. This always
    /// exists since it is at least zero :)
    pub fn len_lo(&self) -> usize {
        self.len_lo
    }

    /// Retries the element's numeric value, if it can be determined
    pub fn num_value(&self) -> Option<i64> {
        let lo = self.num_lo();
        let hi = self.num_hi();
        if lo == hi { Some(lo) } else { None }
    }

    /// Propagate any changes to all nodes which are referenced
    fn update(&mut self) -> Result<(), Error> {
        // Check that this node is consistent before doing any propagation
        if !self.validate() {
            return Err(Error::AnalyzeValidateFailed);
        }

        let validators = self.validators.clone();
        for v in validators.iter().cloned() {
            try!((v.update)(self, &v.args));
        }
        Ok(())
    }

    /// Check that all rules are satisfied
    fn validate(&mut self) -> bool {
        if self.num_hi < self.num_lo { return false; }
        if self.len_hi < self.len_lo { return false; }

        self.validators.iter().all(|rule| (rule.check)(self, &rule.args))
    }

    /// Sets the boolean value
    pub fn set_bool_value(&mut self, val: bool)
                         -> Result<(), Error> {
        match self.bool_val {
            Some(x) => {
                if x != val { return Err(Error::AnalyzeSetBoolMismatch(val)); }
            }
            None => {
                self.bool_val = Some(val);
                if !val {
                    try!(self.set_num_value(0));
                } else if self.num_lo() == 0 && self.num_hi == 1 {
                    // This seems like a special case but actually everything that
                    // is `set_boolean` satisfies it
                    try!(self.set_num_value(1));
                }
                try!(self.update());
            }
        }
        Ok(())
    }

    /// Sets the numeric value
    pub fn set_num_value(&mut self, val: i64) -> Result<(), Error> {
        try!(self.set_num_lo(val));
        self.set_num_hi(val)
    }

    /// Sets the entire value of the 
    pub fn set_value(&mut self, val: &[u8]) -> Result<(), Error> {
        match self.raw_value().map(|x| x.to_vec()) {
            Some(x) => { if &x[..] == val { Ok(()) } else { Err(Error::Unsatisfiable) } }
            None => {
                try!(self.set_len_lo(val.len()));
                try!(self.set_len_hi(val.len()));
                try!(self.set_bool_value(read_scriptbool(val)));
                if let Ok(n) = read_scriptint(val) {
                    try!(self.set_num_lo(n));
                    try!(self.set_num_hi(n));
                }
                try!(self.set_bool_value(read_scriptbool(val)));
                self.raw = Some(val.to_vec());
                Ok(())
            }
        }
    }

    /// Sets a number to be numerically parseable
    pub fn set_numeric(&mut self) -> Result<(), Error> {
        self.set_len_hi(4)
    }

    /// Whether an element could possibly be a number
    pub fn may_be_numeric(&self) -> bool {
        self.len_lo() <= 4
    }

    /// Whether an element could possibly be a signature
    pub fn may_be_signature(&self) -> bool {
        self.len_lo() <= 78 && self.len_hi() >= 77
        // todo check DER encoding
    }

    /// Whether an element could possibly be a pubkey
    pub fn may_be_pubkey(&self) -> bool {
        let s = Secp256k1::with_caps(secp256k1::ContextFlag::None);
        ((self.len_lo() <= 33 && self.len_hi() >= 33) ||
         (self.len_lo() <= 65 && self.len_hi() >= 65)) &&
        (self.raw_value().is_none() || PublicKey::from_slice(&s, self.raw_value().unwrap()).is_ok())
    }

    /// Whether an element could possibly be less than another
    pub fn may_be_lt(&self, other: &AbstractStackElem) -> bool {
        self.num_lo() < other.num_hi() &&
        self.num_value().is_none() || other.num_value().is_none() ||
            self.num_value().unwrap() < other.num_value().unwrap()
    }

    /// Whether an element could possibly be greater than another
    pub fn may_be_gt(&self, other: &AbstractStackElem) -> bool {
        self.num_hi() > other.num_lo() &&
        (self.num_value().is_none() || other.num_value().is_none() ||
         self.num_value().unwrap() > other.num_value().unwrap())
    }

    /// Whether an element could possibly be less than or equal to another
    pub fn may_be_lteq(&self, other: &AbstractStackElem) -> bool {
        self.num_lo() <= other.num_hi() &&
        self.num_value().is_none() || other.num_value().is_none() ||
            self.num_value().unwrap() <= other.num_value().unwrap()
    }

    /// Whether an element could possibly be greater than or equal to another
    pub fn may_be_gteq(&self, other: &AbstractStackElem) -> bool {
        self.num_hi() >= other.num_lo() &&
        (self.num_value().is_none() || other.num_value().is_none() ||
         self.num_value().unwrap() >= other.num_value().unwrap())
    }

    /// Whether an element could possibly be a 20-byte hash
    pub fn may_be_hash160(&self) -> bool {
        self.len_lo() <= 20 && self.len_hi() >= 20
    }

    /// Whether an element could possibly be a 32-byte hash
    pub fn may_be_hash256(&self) -> bool {
        self.len_lo() <= 32 && self.len_hi() >= 32
    }

    /// Sets a number to be an opcode-pushed boolean
    pub fn set_boolean(&mut self) -> Result<(), Error> {
        try!(self.set_len_hi(1));
        try!(self.set_num_lo(0));
        self.set_num_hi(1)
    }

    /// Sets a numeric lower bound on a value
    pub fn set_num_lo(&mut self, value: i64) -> Result<(), Error> {
        if self.num_lo < value {
            self.num_lo = value;
            if value > 0 { try!(self.set_bool_value(true)); }
            if value == 0 && self.num_hi == 0 { try!(self.set_bool_value(false)); }
            try!(self.update());
        }
        Ok(())
    }

    /// Sets a numeric upper bound on a value
    pub fn set_num_hi(&mut self, value: i64) -> Result<(), Error> {
        if self.num_hi > value {
            self.num_hi = value;
            if value < 0 { try!(self.set_bool_value(true)); }
            if value == 0 && self.num_lo == 0 { try!(self.set_bool_value(false)); }
            try!(self.update());
        }
        Ok(())
    }

    /// Sets a lower length bound on a value
    pub fn set_len_lo(&mut self, value: usize) -> Result<(), Error> {
        if self.len_lo < value {
            self.len_lo = value;
            if value > 0 { try!(self.set_bool_value(true)); }
            if value == 0 && self.num_hi == 0 { try!(self.set_bool_value(false)); }
            try!(self.update());
        }
        Ok(())
    }

    /// Sets a upper length bound on a value
    pub fn set_len_hi(&mut self, value: usize) -> Result<(), Error> {
        if self.len_hi > value {
            self.len_hi = value;
            try!(self.update());
        }
        Ok(())
    }

    /// Adds some condition on the element
    pub fn add_validator(&mut self, cond: Validator) -> Result<(), Error> {
        self.validators.push(cond);
        self.update()
    }
}


/// The stack used by the script satisfier
#[derive(Clone)]
pub struct AbstractStack {
    /// Actual elements on the stack
    stack: Vec<usize>,
    /// Actual elements on the altstack
    alt_stack: Vec<usize>,
    /// Stack needed to satisfy the script before execution
    initial_stack: Vec<usize>,
    /// Local allocator to allow cloning; refs are indices into here
    alloc: Vec<AbstractStackElem>
}

impl AbstractStack {
    /// Construct a new empty abstract stack
    pub fn new() -> AbstractStack {
        AbstractStack {
            stack: vec![],
            alt_stack: vec![],
            initial_stack: vec![],
            alloc: vec![]
        }
    }

    fn allocate(&mut self, mut elem: AbstractStackElem) -> usize {
        elem.alloc_index = Some(self.alloc.len());
        self.alloc.push(elem);
        self.alloc.len() - 1
    }

    fn push_initial(&mut self, elem: AbstractStackElem) {
        let idx = self.allocate(elem);
        self.initial_stack.insert(0, idx);
        self.stack.insert(0, idx);
    }

    /// Construct the initial stack in the end
    pub fn build_initial_stack(&self) -> Vec<AbstractStackElem> {
        self.initial_stack.iter().map(|&i| self.alloc[i].clone()).collect()
    }

    /// Increase the stack size to `n`, adding elements to the initial
    /// stack as necessary
    pub fn require_n_elems(&mut self, n: usize) {
        while self.stack.len() < n {
            self.push_initial(AbstractStackElem::new_unknown());
        }
    }

    /// Push a copy of an existing element by index
    pub fn push(&mut self, elem: usize) {
        self.stack.push(elem);
    }

    /// Push a new element
    pub fn push_alloc(&mut self, elem: AbstractStackElem) -> &mut AbstractStackElem {
        let idx = self.allocate(elem);
        self.stack.push(idx);
        &mut self.alloc[idx]
    }


    /// Obtain a mutable element to the top stack element
    pub fn peek_mut(&mut self) -> &mut AbstractStackElem {
        if self.stack.is_empty() {
            self.push_initial(AbstractStackElem::new_unknown());
        }

        &mut self.alloc[*self.stack.last().unwrap()]
    }

    /// Obtain a stackref to the current top element
    pub fn peek_index(&mut self) -> usize {
        if self.stack.is_empty() {
            self.push_initial(AbstractStackElem::new_unknown());
        }
        *self.stack.last().unwrap()
    }

    /// Drop the top stack item
    fn pop(&mut self) -> usize {
        if self.stack.is_empty() {
            self.push_initial(AbstractStackElem::new_unknown());
        }
        self.stack.pop().unwrap()
    }

    /// Obtain a mutable reference to the top stack item, but remove it from the stack
    fn pop_mut(&mut self) -> &mut AbstractStackElem {
        if self.stack.is_empty() {
            self.push_initial(AbstractStackElem::new_unknown());
        }

        &mut self.alloc[self.stack.pop().unwrap()]
    }


    /// Move the top stack item to the altstack
    pub fn top_to_altstack(&mut self) {
        if self.stack.is_empty() {
            self.push_initial(AbstractStackElem::new_unknown());
        }

        let pop = self.stack.pop().unwrap();
        self.alt_stack.push(pop);
    }

    /// Move the top altstack item to the stack, failing if the
    /// altstack is empty. (Note that input scripts pass their
    /// stack to the output script but /not/ the altstack, so
    /// there is no input that can make an empty altstack nonempty.)
    pub fn top_from_altstack(&mut self) -> Result<(), Error> {
        match self.alt_stack.pop() {
            Some(x) => { self.stack.push(x); Ok(()) }
            None => Err(Error::PopEmptyStack)
        }
    }

    /// Length of the current stack
    fn len(&self) -> usize {
        self.stack.len()
    }

    /// Delete an element from the middle of the current stack
    fn remove(&mut self, idx: usize) {
        self.stack.remove(idx);
    }
}

impl ops::Index<usize> for AbstractStack {
    type Output = usize;
    #[inline]
    fn index(&self, index: usize) -> &usize {
        &self.stack[index]
    }
}

impl ops::Index<ops::Range<usize>> for AbstractStack {
    type Output = [usize];
    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[usize] {
        &self.stack[index]
    }
}

impl ops::Index<ops::RangeTo<usize>> for AbstractStack {
    type Output = [usize];
    #[inline]
    fn index(&self, index: ops::RangeTo<usize>) -> &[usize] {
        &self.stack[index]
    }
}

impl ops::Index<ops::RangeFrom<usize>> for AbstractStack {
    type Output = [usize];
    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[usize] {
        &self.stack[index]
    }
}

impl ops::Index<ops::RangeFull> for AbstractStack {
    type Output = [usize];
    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[usize] {
        &self.stack[..]
    }
}

impl ops::IndexMut<usize> for AbstractStack {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut usize {
        &mut self.stack[index]
    }
}

impl ops::IndexMut<ops::Range<usize>> for AbstractStack {
    #[inline]
    fn index_mut(&mut self, index: ops::Range<usize>) -> &mut [usize] {
        &mut self.stack[index]
    }
}

impl ops::IndexMut<ops::RangeTo<usize>> for AbstractStack {
    #[inline]
    fn index_mut(&mut self, index: ops::RangeTo<usize>) -> &mut [usize] {
        &mut self.stack[index]
    }
}

impl ops::IndexMut<ops::RangeFrom<usize>> for AbstractStack {
    #[inline]
    fn index_mut(&mut self, index: ops::RangeFrom<usize>) -> &mut [usize] {
        &mut self.stack[index]
    }
}

impl ops::IndexMut<ops::RangeFull> for AbstractStack {
    #[inline]
    fn index_mut(&mut self, _: ops::RangeFull) -> &mut [usize] {
        &mut self.stack[..]
    }
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.visit_str(&self.to_string())
    }
}

/// A single iteration of a script execution
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TraceIteration {
    index: usize,
    op_count: usize,
    opcode: opcodes::All,
    executed: bool,
    errored: bool,
    effect: opcodes::Class,
    stack: Vec<String>
}

/// A full trace of a script execution
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ScriptTrace {
    /// A copy of the script
    pub script: Script,
    /// A copy of the script's initial stack, hex-encoded
    pub initial_stack: Vec<String>,
    /// A list of iterations
    pub iterations: Vec<TraceIteration>,
    /// An error if one was returned, or None
    pub error: Option<Error>
}

/// Hashtype of a transaction, encoded in the last byte of a signature,
/// specifically in the last 5 bits `byte & 31`
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum SigHashType {
    /// 0x1: Sign all outputs
    All,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single,
    /// ???: Anything else is a non-canonical synonym for SigHashAll, for example
    /// zero appears a few times in the chain
    Unknown
}

impl SigHashType {
     /// Returns a SigHashType along with a boolean indicating whether
     /// the `ANYONECANPAY` flag is set, read from the last byte of a signature.
     fn from_signature(signature: &[u8]) -> (SigHashType, bool) {
         let byte = signature[signature.len() - 1];
         let sighash = match byte & 0x1f {
             1 => SigHashType::All,
             2 => SigHashType::None,
             3 => SigHashType::Single,
             _ => SigHashType::Unknown
         };
         (sighash, (byte & 0x80) != 0)
     }
}

/// A structure that can hold either a slice or vector, as necessary
#[derive(Clone, Debug)]
pub enum MaybeOwned<'a> {
    /// Freshly llocated memory
    Owned(Vec<u8>),
    /// Pointer into the original script
    Borrowed(&'a [u8])
}

impl<'a> PartialEq for MaybeOwned<'a> {
    #[inline]
    fn eq(&self, other: &MaybeOwned) -> bool { &self[..] == &other[..] }
}

impl<'a> Eq for MaybeOwned<'a> {}

impl<'a> ops::Index<usize> for MaybeOwned<'a> {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        match *self {
            MaybeOwned::Owned(ref v) => &v[index],
            MaybeOwned::Borrowed(ref s) => &s[index]
        }
    }
}

impl<'a> ops::Index<ops::Range<usize>> for MaybeOwned<'a> {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        match *self {
            MaybeOwned::Owned(ref v) => &v[index],
            MaybeOwned::Borrowed(ref s) => &s[index]
        }
    }
}

impl<'a> ops::Index<ops::RangeTo<usize>> for MaybeOwned<'a> {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeTo<usize>) -> &[u8] {
        match *self {
            MaybeOwned::Owned(ref v) => &v[index],
            MaybeOwned::Borrowed(ref s) => &s[index]
        }
    }
}

impl<'a> ops::Index<ops::RangeFrom<usize>> for MaybeOwned<'a> {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        match *self {
            MaybeOwned::Owned(ref v) => &v[index],
            MaybeOwned::Borrowed(ref s) => &s[index]
        }
    }
}

impl<'a> ops::Index<ops::RangeFull> for MaybeOwned<'a> {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        match *self {
            MaybeOwned::Owned(ref v) => &v[..],
            MaybeOwned::Borrowed(ref s) => &s[..]
        }
    }
}

impl<'a> MaybeOwned<'a> {
    /// The number of bytes stored in the vector
    #[inline]
    fn len(&self) -> usize {
        match *self {
            MaybeOwned::Owned(ref v) => v.len(),
            MaybeOwned::Borrowed(ref s) => s.len()
        }
    }
}

static SCRIPT_TRUE: &'static [u8] = &[0x01];
static SCRIPT_FALSE: &'static [u8] = &[0x00];

/// Helper to encode an integer in script format
fn build_scriptint(n: i64) -> Vec<u8> {
    if n == 0 { return vec![] }

    let neg = n < 0;

    let mut abs = if neg { -n } else { n } as usize;
    let mut v = vec![];
    while abs > 0xFF {
        v.push((abs & 0xFF) as u8);
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        v.push(abs as u8);
        v.push(if neg { 0x80u8 } else { 0u8 });
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        v.push(abs as u8);
    }
    v
}

/// Helper to decode an integer in script format
/// Notice that this fails on overflow: the result is the same as in
/// bitcoind, that only 4-byte signed-magnitude values may be read as
/// numbers. They can be added or subtracted (and a long time ago,
/// multiplied and divided), and this may result in numbers which
/// can't be written out in 4 bytes or less. This is ok! The number
/// just can't be read as a number again.
/// This is a bit crazy and subtle, but it makes sense: you can load
/// 32-bit numbers and do anything with them, which back when mult/div
/// was allowed, could result in up to a 64-bit number. We don't want
/// overflow since that's suprising --- and we don't want numbers that
/// don't fit in 64 bits (for efficiency on modern processors) so we
/// simply say, anything in excess of 32 bits is no longer a number.
/// This is basically a ranged type implementation.
pub fn read_scriptint(v: &[u8]) -> Result<i64, Error> {
    let len = v.len();
    if len == 0 { return Ok(0); }
    if len > 4 { return Err(Error::NumericOverflow); }

    let (mut ret, sh) = v.iter()
                         .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[len - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    Ok(ret)
}

/// This is like "read_scriptint then map 0 to false and everything
/// else as true", except that the overflow rules don't apply.
#[inline]
pub fn read_scriptbool(v: &[u8]) -> bool {
    !(v.is_empty() ||
        ((v[v.len() - 1] == 0 || v[v.len() - 1] == 0x80) &&
         v.iter().rev().skip(1).all(|&w| w == 0)))
}

/// Read a script-encoded unsigned integer
pub fn read_uint(data: &[u8], size: usize) -> Result<usize, Error> {
    if data.len() < size {
        Err(Error::EarlyEndOfScript)
    } else {
        let mut ret = 0;
        for (i, item) in data.iter().take(size).enumerate() {
            ret += (*item as usize) << (i * 8);
        }
        Ok(ret)
    }
}

/// Check a signature -- returns an error that is currently just translated
/// into a 0/1 to push onto the script stack
fn check_signature(secp: &Secp256k1, sig_slice: &[u8], pk_slice: &[u8], script: Vec<u8>,
                   tx: &Transaction, input_index: usize) -> Result<(), Error> {

    // Check public key
    let pubkey = PublicKey::from_slice(secp, pk_slice);
    if pubkey.is_err() {
        return Err(Error::BadPublicKey);
    }
    let pubkey = pubkey.unwrap();

    // Check signature and hashtype
    if sig_slice.len() == 0 {
        return Err(Error::BadSignature);
    }
    let (hashtype, anyone_can_pay) = SigHashType::from_signature(sig_slice);

    // Compute the transaction data to be hashed
    let mut tx_copy = Transaction { version: tx.version, lock_time: tx.lock_time,
                                    input: Vec::with_capacity(tx.input.len()),
                                    output: tx.output.clone() };

    // Put the script into an Option so that we can move it (via take_unwrap())
    // in the following branch/loop without the move-checker complaining about
    // multiple moves.
    let mut script = Some(script);
    if anyone_can_pay {
        // For anyone-can-pay transactions we replace the whole input array
        // with just the current input, to ensure the others have no effect.
        let mut old_input = tx.input[input_index].clone();
        old_input.script_sig = Script(script.take().unwrap().into_boxed_slice());
        tx_copy.input = vec![old_input];
    } else {
        // Otherwise we keep all the inputs, blanking out the others and even
        // resetting their sequence no. if appropriate
        for (n, input) in tx.input.iter().enumerate() {
            // Zero out the scripts of other inputs
            let mut new_input = TxIn { prev_hash: input.prev_hash,
                                       prev_index: input.prev_index,
                                       sequence: input.sequence,
                                       script_sig: Script::new() };
            if n == input_index {
                new_input.script_sig = Script(script.take().unwrap().into_boxed_slice());
            } else {
                new_input.script_sig = Script::new();
                // If we aren't signing them, also zero out the sequence number
                if hashtype == SigHashType::Single || hashtype == SigHashType::None {
                    new_input.sequence = 0;
                }
            }
            tx_copy.input.push(new_input);
        }
    }

    // Erase outputs as appropriate
    let mut sighash_single_bug = false;
    match hashtype {
        SigHashType::None => { tx_copy.output = vec![]; }
        SigHashType::Single => {
            if input_index < tx_copy.output.len() {
                let mut new_outs = Vec::with_capacity(input_index + 1);
                for _ in 0..input_index {
                    new_outs.push(Default::default())
                }
                new_outs.push(tx_copy.output.swap_remove(input_index));
                tx_copy.output = new_outs;
            } else {
                sighash_single_bug = true;
            }
        }
        SigHashType::All | SigHashType::Unknown => {}
    }

    let signature_hash = if sighash_single_bug {
        vec![1, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0]
    } else {
        let mut data_to_sign = serialize(&tx_copy).unwrap();
        data_to_sign.push(*sig_slice.last().unwrap());
        data_to_sign.push(0);
        data_to_sign.push(0);
        data_to_sign.push(0);
        serialize(&Sha256dHash::from_data(&data_to_sign[..])).unwrap()
    };

    // We can unwrap -- only failure mode is on length, which is fixed to 32
    let msg = secp256k1::Message::from_slice(&signature_hash[..]).unwrap();
    // TODO: both from_der_lax and normalize() should not be used once BIP66 is accepted
    let mut sig = try!(secp256k1::Signature::from_der_lax(secp, sig_slice).map_err(Error::Ecdsa));
    // Normalize it
    sig.normalize_s(secp);

    Secp256k1::verify(secp, &msg, &sig, &pubkey).map_err(Error::Ecdsa)
}

// Macro to translate English stack instructions into Rust code.
// All number are references to stack positions: 1 is the top,
// 2 is the second-to-top, etc. The numbers do not change within
// an opcode; to delete the top two items do `drop 1 drop 2`
// rather than `drop 1 drop 1`, which will fail.
// This is useful for only about a dozen opcodes, but those ones
// were really hard to read and verify -- see OP_PICK and OP_ROLL
// for an example of what Rust vector-stack manipulation looks
// like.
// Commands can be given in any order, except that `require` should
// always come first and `drop` should always come last, to avoid
// surprises.
macro_rules! stack_opcode {
    ($stack:ident: $($cmd:ident $args:tt);*) => ({
        // Record top
        let mut top = $stack.len();
        &mut top;  // shut up warnings in case top is either unread or unmutated
        $(stack_opcode_internal!($cmd: $stack, top, $args);)*
    });
}

// The actual commands available to the above macro
macro_rules! stack_opcode_internal {
    (require: $stack:ident, $top:ident, $r:expr) => ({
        $stack.require_n_elems($r);
        $top = $stack.len();
    });
    (copy: $stack:ident, $top:ident, $c:expr) => ({
        if $top < $c { return Err(Error::PopEmptyStack); }
        let elem = $stack[$top - $c].clone();
        $stack.push(elem);
    });
    (swap: $stack:ident, $top:ident, ($a:expr, $b:expr)) => ({
        if $top < $a || $top < $b { return Err(Error::PopEmptyStack); }
        (&mut $stack[..]).swap($top - $a, $top - $b);
    });
    (perm: $stack:ident, $top:ident, ($first:expr, $($i:expr),*)) => ({
        if $top < $first { return Err(Error::PopEmptyStack); }
        let first = $first;
        $(
            if $top < $i { return Err(Error::PopEmptyStack); }
            (&mut $stack[..]).swap($top - first, $top - $i);
        )*
    });
    (drop: $stack:ident, $top:ident, $d:expr) => ({
        if $top < $d { return Err(Error::PopEmptyStack); }
        $stack.remove($top - $d);
    });
}

/// Macro to translate numerical operations into stack ones
macro_rules! num_opcode {
    ($stack:ident($($var:ident),*): $op:expr) => ({
        $(
            let $var = try!(read_scriptint(&match $stack.pop() {
                Some(elem) => elem,
                None => { return Err(Error::PopEmptyStack); }
            }[..]));
        )*
        $stack.push(MaybeOwned::Owned(build_scriptint($op)));
        // Return a tuple of all the variables
        ($( $var ),*)
    });
}

macro_rules! unary_opcode_satisfy {
    ($stack:ident, $op:ident) => ({
        let one = $stack.pop();
        let cond = $stack.push_alloc(AbstractStackElem::new_unknown());
        try!(cond.add_validator(Validator { args: vec![one],
                                            check: check::$op,
                                            update: update::$op }));
    })
}

macro_rules! boolean_opcode_satisfy {
    ($stack:ident, unary $op:ident) => ({
        let one = $stack.pop();
        let cond = $stack.push_alloc(AbstractStackElem::new_unknown());
        try!(cond.set_boolean());
        try!(cond.add_validator(Validator { args: vec![one],
                                            check: check::$op,
                                            update: update::$op }));
    });
    ($stack:ident, binary $op:ident) => ({
        let one = $stack.pop();
        let two = $stack.pop();
        let cond = $stack.push_alloc(AbstractStackElem::new_unknown());
        try!(cond.set_boolean());
        try!(cond.add_validator(Validator { args: vec![two, one],
                                            check: check::$op,
                                            update: update::$op }));
    });
    ($stack:ident, ternary $op:ident) => ({
        let one = $stack.pop();
        let two = $stack.pop();
        let three = $stack.pop();
        let mut cond = $stack.push_alloc(AbstractStackElem::new_unknown());
        try!(cond.set_boolean());
        try!(cond.add_validator(Validator { args: vec![three, two, one],
                                            check: check::$op,
                                            update: update::$op }));
    });
}

/// Macro to translate hashing operations into stack ones
macro_rules! hash_opcode {
    ($stack:ident, $hash:ident) => ({
        match $stack.pop() {
            None => { return Err(Error::PopEmptyStack); }
            Some(v) => {
                let mut engine = $hash::new();
                engine.input(&v[..]);
                let mut ret = Vec::with_capacity(engine.output_bits() / 8);
                // Force-set the length even though the vector is uninitialized
                // This is OK only because u8 has no destructor
                unsafe { ret.set_len(engine.output_bits() / 8); }
                engine.result(&mut ret);
                $stack.push(MaybeOwned::Owned(ret));
            }
        }
    });
}

// OP_VERIFY macro
macro_rules! op_verify {
    ($stack:expr, $err:expr) => (
        match $stack.last().map(|v| read_scriptbool(&v[..])) {
            None => { return Err(Error::VerifyEmptyStack); }
            Some(false) => { return Err($err); }
            Some(true) => { $stack.pop(); }
        }
    )
}

macro_rules! op_verify_satisfy {
    ($stack:expr) => ({
        try!($stack.peek_mut().set_bool_value(true));
        $stack.pop();
    })
}

impl Script {
    /// Creates a new empty script
    pub fn new() -> Script { Script(vec![].into_boxed_slice()) }

    /// The length in bytes of the script
    pub fn len(&self) -> usize { self.0.len() }

    /// Whether the script is the empty script
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Convert the script into a byte vector
    pub fn into_vec(self) -> Vec<u8> { self.0.into_vec() }

    /// Trace a script
    pub fn trace<'a>(&'a self, secp: &Secp256k1, stack: &mut Vec<MaybeOwned<'a>>,
                     input_context: Option<(&Transaction, usize)>)
                    -> ScriptTrace {
        let mut trace = ScriptTrace {
            script: self.clone(),
            initial_stack: stack.iter().map(|elem| (&elem[..]).to_hex()).collect(),
            iterations: vec![],
            error: None
        };

        match self.evaluate(secp, stack, input_context, Some(&mut trace.iterations)) {
            Ok(_) => {},
            Err(e) => { trace.error = Some(e.clone()); }
        }
        trace
    }

    /// Evaluate the script, modifying the stack in place
    pub fn evaluate<'a>(&'a self, secp: &Secp256k1, stack: &mut Vec<MaybeOwned<'a>>,
                        input_context: Option<(&Transaction, usize)>,
                        mut trace: Option<&mut Vec<TraceIteration>>)
                       -> Result<(), Error> {
        let mut codeseparator_index = 0;
        let mut exec_stack = vec![];
        let mut alt_stack = vec![];

        let mut index = 0;
        let mut op_count = 0;
        while index < self.0.len() {
            let executing = exec_stack.iter().all(|e| *e);
            let byte = self.0[index];
            // Write out the trace, except the stack which we don't know yet
            if let Some(ref mut t) = trace {
                let opcode = opcodes::All::from(byte);
                t.push(TraceIteration {
                    index: index,
                    opcode: opcode,
                    executed: executing,
                    errored: true,
                    op_count: op_count,
                    effect: opcode.classify(),
                    stack: vec!["<failed to execute opcode>".to_owned()]
                });
            }
            op_count += 1;
            index += 1;
            // The definitions of all these categories are in opcodes.rs
            match (executing, opcodes::All::from(byte).classify()) {
                // Illegal operations mean failure regardless of execution state
                (_, opcodes::Class::IllegalOp)             => return Err(Error::IllegalOpcode),
                // Push number
                (true, opcodes::Class::PushNum(n))     => stack.push(MaybeOwned::Owned(build_scriptint(n as i64))),
                // Return operations mean failure, but only if executed
                (true, opcodes::Class::ReturnOp)         => return Err(Error::ExecutedReturn),
                // Data-reading statements still need to read, even when not executing
                (_, opcodes::Class::PushBytes(n)) => {
                    let n = n as usize;
                    if self.0.len() < index + n { return Err(Error::EarlyEndOfScript); }
                    if executing { stack.push(MaybeOwned::Borrowed(&self.0[index..index + n])); }
                    index += n;
                }
                (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1)) => {
                    if self.0.len() < index + 1 { return Err(Error::EarlyEndOfScript); }
                    let n = try!(read_uint(&self.0[index..], 1));
                    if self.0.len() < index + 1 + n { return Err(Error::EarlyEndOfScript); }
                    if executing { stack.push(MaybeOwned::Borrowed(&self.0[index + 1..index + n + 1])); }
                    index += 1 + n;
                }
                (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2)) => {
                    if self.0.len() < index + 2 { return Err(Error::EarlyEndOfScript); }
                    let n = try!(read_uint(&self.0[index..], 2));
                    if self.0.len() < index + 2 + n { return Err(Error::EarlyEndOfScript); }
                    if executing { stack.push(MaybeOwned::Borrowed(&self.0[index + 2..index + n + 2])); }
                    index += 2 + n;
                }
                (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4)) => {
                    if self.0.len() < index + 4 { return Err(Error::EarlyEndOfScript); }
                    let n = try!(read_uint(&self.0[index..], 4));
                    if self.0.len() < index + 4 + n { return Err(Error::EarlyEndOfScript); }
                    if executing { stack.push(MaybeOwned::Borrowed(&self.0[index + 4..index + n + 4])); }
                    index += 4 + n;
                }
                // If-statements take effect when not executing
                (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_IF)) |
                (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_NOTIF)) => exec_stack.push(false),
                (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_ELSE)) => {
                    match exec_stack.last_mut() {
                        Some(ref_e) => { *ref_e = !*ref_e }
                        None => { return Err(Error::ElseWithoutIf); }
                    }
                }
                (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_ENDIF)) => {
                    if exec_stack.pop().is_none() {
                        return Err(Error::EndifWithoutIf);
                    }
                }
                // No-ops and non-executed operations do nothing
                (true, opcodes::Class::NoOp) | (false, _) => {}
                // Actual opcodes
                (true, opcodes::Class::Ordinary(op)) => {
                    match op {
                        opcodes::Ordinary::OP_PUSHDATA1 | opcodes::Ordinary::OP_PUSHDATA2 | opcodes::Ordinary::OP_PUSHDATA4 => {
                            // handled above
                        }
                        opcodes::Ordinary::OP_IF => {
                            match stack.pop().map(|v| read_scriptbool(&v[..])) {
                                None => { return Err(Error::IfEmptyStack); }
                                Some(b) => exec_stack.push(b)
                            }
                        }
                        opcodes::Ordinary::OP_NOTIF => {
                            match stack.pop().map(|v| read_scriptbool(&v[..])) {
                                None => { return Err(Error::IfEmptyStack); }
                                Some(b) => exec_stack.push(!b),
                            }
                        }
                        opcodes::Ordinary::OP_ELSE => {
                            match exec_stack.last_mut() {
                                Some(ref_e) => { *ref_e = !*ref_e }
                                None => { return Err(Error::ElseWithoutIf); }
                            }
                        }
                        opcodes::Ordinary::OP_ENDIF => {
                            if exec_stack.pop().is_none() {
                                return Err(Error::EndifWithoutIf);
                            }
                        }
                        opcodes::Ordinary::OP_VERIFY => op_verify!(stack, Error::VerifyFailed),
                        opcodes::Ordinary::OP_TOALTSTACK => {
                            match stack.pop() {
                                None => { return Err(Error::PopEmptyStack); }
                                Some(elem) => { alt_stack.push(elem); }
                            }
                        }
                        opcodes::Ordinary::OP_FROMALTSTACK => {
                            match alt_stack.pop() {
                                None => { return Err(Error::PopEmptyStack); }
                                Some(elem) => { stack.push(elem); }
                            }
                        }
                        opcodes::Ordinary::OP_2DROP => stack_opcode!(stack: drop 1; drop 2),
                        opcodes::Ordinary::OP_2DUP  => stack_opcode!(stack: copy 2; copy 1),
                        opcodes::Ordinary::OP_3DUP  => stack_opcode!(stack: copy 3; copy 2; copy 1),
                        opcodes::Ordinary::OP_2OVER => stack_opcode!(stack: copy 4; copy 3),
                        opcodes::Ordinary::OP_2ROT  => stack_opcode!(stack: perm (1, 3, 5);
                                                                            perm (2, 4, 6)),
                        opcodes::Ordinary::OP_2SWAP => stack_opcode!(stack: swap (2, 4); swap (1, 3)),
                        opcodes::Ordinary::OP_DROP  => stack_opcode!(stack: drop 1),
                        opcodes::Ordinary::OP_DUP   => stack_opcode!(stack: copy 1),
                        opcodes::Ordinary::OP_NIP   => stack_opcode!(stack: drop 2),
                        opcodes::Ordinary::OP_OVER  => stack_opcode!(stack: copy 2),
                        opcodes::Ordinary::OP_PICK => {
                            let n = match stack.pop() {
                                Some(data) => try!(read_scriptint(&data[..])),
                                None => { return Err(Error::PopEmptyStack); }
                            };
                            if n < 0 { return Err(Error::NegativePick); }
                            let n = n as usize;
                            stack_opcode!(stack: copy (n + 1))
                        }
                        opcodes::Ordinary::OP_ROLL => {
                            let n = match stack.pop() {
                                Some(data) => try!(read_scriptint(&data[..])),
                                None => { return Err(Error::PopEmptyStack); }
                            };
                            if n < 0 { return Err(Error::NegativeRoll); }
                            let n = n as usize;
                            stack_opcode!(stack: copy (n + 1); drop (n + 1))
                        }
                        opcodes::Ordinary::OP_ROT  => stack_opcode!(stack: perm (1, 2, 3)),
                        opcodes::Ordinary::OP_SWAP => stack_opcode!(stack: swap (1, 2)),
                        opcodes::Ordinary::OP_TUCK => stack_opcode!(stack: copy 2; copy 1; drop 2),
                        opcodes::Ordinary::OP_IFDUP => {
                            match stack.last().map(|v| read_scriptbool(&v[..])) {
                                None => { return Err(Error::IfEmptyStack); }
                                Some(false) => {}
                                Some(true) => { stack_opcode!(stack: copy 1); }
                            }
                        }
                        opcodes::Ordinary::OP_DEPTH => {
                            let len = stack.len() as i64;
                            stack.push(MaybeOwned::Owned(build_scriptint(len)));
                        }
                        opcodes::Ordinary::OP_SIZE => {
                            match stack.last().map(|v| v.len() as i64) {
                                None => { return Err(Error::IfEmptyStack); }
                                Some(n) => { stack.push(MaybeOwned::Owned(build_scriptint(n))); }
                            }
                        }
                        opcodes::Ordinary::OP_EQUAL | opcodes::Ordinary::OP_EQUALVERIFY => {
                            if stack.len() < 2 { return Err(Error::PopEmptyStack); }
                            let a = stack.pop().unwrap();
                            let b = stack.pop().unwrap();
                            stack.push(MaybeOwned::Borrowed(if a == b { SCRIPT_TRUE } else { SCRIPT_FALSE }));
                            if op == opcodes::Ordinary::OP_EQUALVERIFY {
                                op_verify!(stack, Error::EqualVerifyFailed((&a[..]).to_hex(),
                                                                           (&b[..]).to_hex()));
                            }
                        }
                        opcodes::Ordinary::OP_1ADD => { num_opcode!(stack(a): a + 1); }
                        opcodes::Ordinary::OP_1SUB => { num_opcode!(stack(a): a - 1); }
                        opcodes::Ordinary::OP_NEGATE => { num_opcode!(stack(a): -a); }
                        opcodes::Ordinary::OP_ABS => { num_opcode!(stack(a): a.abs()); }
                        opcodes::Ordinary::OP_NOT => { num_opcode!(stack(a): if a == 0 {1} else {0}); }
                        opcodes::Ordinary::OP_0NOTEQUAL => { num_opcode!(stack(a): if a != 0 {1} else {0}); }
                        opcodes::Ordinary::OP_ADD => { num_opcode!(stack(b, a): a + b); }
                        opcodes::Ordinary::OP_SUB => { num_opcode!(stack(b, a): a - b); }
                        opcodes::Ordinary::OP_BOOLAND => { num_opcode!(stack(b, a): if a != 0 && b != 0 {1} else {0}); }
                        opcodes::Ordinary::OP_BOOLOR => { num_opcode!(stack(b, a): if a != 0 || b != 0 {1} else {0}); }
                        opcodes::Ordinary::OP_NUMEQUAL => { num_opcode!(stack(b, a): if a == b {1} else {0}); }
                        opcodes::Ordinary::OP_NUMNOTEQUAL => { num_opcode!(stack(b, a): if a != b {1} else {0}); }
                        opcodes::Ordinary::OP_NUMEQUALVERIFY => {
                            let (b, a) = num_opcode!(stack(b, a): if a == b {1} else {0});
                            op_verify!(stack, Error::NumEqualVerifyFailed(a, b));
                        }
                        opcodes::Ordinary::OP_LESSTHAN => { num_opcode!(stack(b, a): if a < b {1} else {0}); }
                        opcodes::Ordinary::OP_GREATERTHAN => { num_opcode!(stack(b, a): if a > b {1} else {0}); }
                        opcodes::Ordinary::OP_LESSTHANOREQUAL => { num_opcode!(stack(b, a): if a <= b {1} else {0}); }
                        opcodes::Ordinary::OP_GREATERTHANOREQUAL => { num_opcode!(stack(b, a): if a >= b {1} else {0}); }
                        opcodes::Ordinary::OP_MIN => { num_opcode!(stack(b, a): if a < b {a} else {b}); }
                        opcodes::Ordinary::OP_MAX => { num_opcode!(stack(b, a): if a > b {a} else {b}); }
                        opcodes::Ordinary::OP_WITHIN => { num_opcode!(stack(c, b, a): if b <= a && a < c {1} else {0}); }
                        opcodes::Ordinary::OP_RIPEMD160 => hash_opcode!(stack, Ripemd160),
                        opcodes::Ordinary::OP_SHA1 => hash_opcode!(stack, Sha1),
                        opcodes::Ordinary::OP_SHA256 => hash_opcode!(stack, Sha256),
                        opcodes::Ordinary::OP_HASH160 => {
                            hash_opcode!(stack, Sha256);
                            hash_opcode!(stack, Ripemd160);
                        }
                        opcodes::Ordinary::OP_HASH256 => {
                            hash_opcode!(stack, Sha256);
                            hash_opcode!(stack, Sha256);
                        }
                        opcodes::Ordinary::OP_CODESEPARATOR => { codeseparator_index = index; }
                        opcodes::Ordinary::OP_CHECKSIG | opcodes::Ordinary::OP_CHECKSIGVERIFY => {
                            if stack.len() < 2 { return Err(Error::PopEmptyStack); }

                            let pk = stack.pop().unwrap();
                            let pk_slice = &pk[..];
                            let sig = stack.pop().unwrap();
                            let sig_slice = &sig[..];

                            // Compute the section of script that needs to be hashed: everything
                            // from the last CODESEPARATOR, except the signature itself.
                            let mut script = (&self.0[codeseparator_index..]).to_vec();
                            let remove = Builder::new().push_slice(sig_slice);
                            script_find_and_remove(&mut script, &remove[..]);
                            // Also all of the OP_CODESEPARATORS, even the unevaluated ones
                            script_find_and_remove(&mut script, &[opcodes::Ordinary::OP_CODESEPARATOR as u8]);

                            // This is as far as we can go without a transaction, so fail here
                            if input_context.is_none() { return Err(Error::NoTransaction); }
                            // Otherwise unwrap it
                            let (tx, input_index) = input_context.unwrap();

                            match check_signature(secp, sig_slice, pk_slice, script, tx, input_index) {
                                Ok(()) => stack.push(MaybeOwned::Borrowed(SCRIPT_TRUE)),
                                _ => stack.push(MaybeOwned::Borrowed(SCRIPT_FALSE))
                            }
                            if op == opcodes::Ordinary::OP_CHECKSIGVERIFY { op_verify!(stack, Error::VerifyFailed); }
                        }
                        opcodes::Ordinary::OP_CHECKMULTISIG | opcodes::Ordinary::OP_CHECKMULTISIGVERIFY => {
                            // Read all the keys
                            if stack.len() < 1 { return Err(Error::PopEmptyStack); }
                            let n_keys = try!(read_scriptint(&stack.pop().unwrap()[..]));
                            if n_keys < 0 || n_keys > 20 {
                                return Err(Error::MultisigBadKeyCount(n_keys as isize));
                            }

                            if (stack.len() as i64) < n_keys { return Err(Error::PopEmptyStack); }
                            let mut keys = Vec::with_capacity(n_keys as usize);
                            for _ in 0..n_keys {
                                keys.push(stack.pop().unwrap());
                            }

                            // Read all the signatures
                            if stack.len() < 1 { return Err(Error::PopEmptyStack); }
                            let n_sigs = try!(read_scriptint(&stack.pop().unwrap()[..]));
                            if n_sigs < 0 || n_sigs > n_keys {
                                return Err(Error::MultisigBadSigCount(n_sigs as isize));
                            }

                            if (stack.len() as i64) < n_sigs { return Err(Error::PopEmptyStack); }
                            let mut sigs = Vec::with_capacity(n_sigs as usize);
                            for _ in 0..n_sigs {
                                sigs.push(stack.pop().unwrap());
                            }

                            // Pop one more element off the stack to be replicate a consensus bug
                            if stack.pop().is_none() { return Err(Error::PopEmptyStack); }

                            // Compute the section of script that needs to be hashed: everything
                            // from the last CODESEPARATOR, except the signatures themselves.
                            let mut script = (&self.0[codeseparator_index..]).to_vec();
                            for sig in &sigs {
                                let remove = Builder::new().push_slice(&sig[..]);
                                script_find_and_remove(&mut script, &remove[..]);
                                script_find_and_remove(&mut script, &[opcodes::Ordinary::OP_CODESEPARATOR as u8]);
                            }

                            // This is as far as we can go without a transaction, so fail here
                            if input_context.is_none() { return Err(Error::NoTransaction); }
                            // Otherwise unwrap it
                            let (tx, input_index) = input_context.unwrap();

                            // Check signatures
                            let mut key_iter = keys.iter();
                            let mut sig_iter = sigs.iter();
                            let mut key = key_iter.next();
                            let mut sig = sig_iter.next();
                            loop {
                                match (key, sig) {
                                    // Try to validate the signature with the given key
                                    (Some(k), Some(s)) => {
                                        // Move to the next signature if it is valid for the current key
                                        if check_signature(secp, &s[..], &k[..], script.clone(), tx, input_index).is_ok() {
                                            sig = sig_iter.next();
                                        }
                                        // Move to the next key in any case
                                        key = key_iter.next();
                                    }
                                    // Run out of signatures, success
                                    (_, None) => {
                                        stack.push(MaybeOwned::Borrowed(SCRIPT_TRUE));
                                        break;
                                    }
                                    // Run out of keys to match to signatures, fail
                                    (None, Some(_)) => {
                                        stack.push(MaybeOwned::Borrowed(SCRIPT_FALSE));
                                        break;
                                    }
                                }
                            }
                            if op == opcodes::Ordinary::OP_CHECKMULTISIGVERIFY { op_verify!(stack, Error::VerifyFailed); }
                        }
                    } // end opcode match
                } // end classification match
            } // end loop
            // Store the stack in the trace
            trace.as_mut().map(|t|
                t.last_mut().map(|t| {
                    t.errored = false;
                    t.stack = stack.iter().map(|elem| (&elem[..]).to_hex()).collect();
                })
            );
        }
        Ok(())
    }

    /// Checks whether a script pubkey is a p2sh output
    #[inline]
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23 &&
        self.0[0] == opcodes::All::OP_HASH160 as u8 &&
        self.0[1] == opcodes::All::OP_PUSHBYTES_20 as u8 &&
        self.0[22] == opcodes::All::OP_EQUAL as u8
    }

    /// Whether a script can be proven to have no satisfying input
    pub fn is_provably_unspendable(&self) -> bool {
        match self.satisfy() {
            Ok(_) | Err(Error::Unanalyzable) => false,
            Err(_) => true
        }
    }

    /// Evaluate the script to determine whether any possible input will cause it
    /// to accept. Returns true if it is guaranteed to fail; false otherwise.
    pub fn satisfy(&self) -> Result<Vec<AbstractStackElem>, Error> {
        fn recurse(script: &[u8],
                   mut stack: AbstractStack,
                   mut exec_stack: Vec<bool>,
                   depth: usize) -> Result<Vec<AbstractStackElem>, Error> {

            // Avoid doing more than 64k forks
            if depth > 16 { return Err(Error::InterpreterStackOverflow); }

            let mut index = 0;
            while index < script.len() {
                let executing = exec_stack.iter().all(|e| *e);
                let byte = script[index];
                index += 1;
                // The definitions of all these categories are in opcodes.rs
                match (executing, opcodes::All::from(byte).classify()) {
                    // Illegal operations mean failure regardless of execution state
                    (_, opcodes::Class::IllegalOp)         => return Err(Error::IllegalOpcode),
                    // Push number
                    (true, opcodes::Class::PushNum(n)) => { stack.push_alloc(AbstractStackElem::new_num(n as i64)); },
                    // Return operations mean failure, but only if executed
                    (true, opcodes::Class::ReturnOp)     => return Err(Error::ExecutedReturn),
                    // Data-reading statements still need to read, even when not executing
                    (_, opcodes::Class::PushBytes(n)) => {
                        let n = n as usize;
                        if script.len() < index + n { return Err(Error::EarlyEndOfScript); }
                        if executing {
                            stack.push_alloc(AbstractStackElem::new_raw(&script[index..index + n]));
                        }
                        index += n;
                    }
                    (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1)) => {
                        if script.len() < index + 1 { return Err(Error::EarlyEndOfScript); }
                        let n = match read_uint(&script[index..], 1) {
                            Ok(n) => n,
                            Err(_) => { return Err(Error::EarlyEndOfScript); }
                        };
                        if script.len() < index + 1 + n { return Err(Error::EarlyEndOfScript); }
                        if executing {
                            stack.push_alloc(AbstractStackElem::new_raw(&script[index + 1..index + n + 1]));
                        }
                        index += 1 + n;
                    }
                    (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2)) => {
                        if script.len() < index + 2 { return Err(Error::EarlyEndOfScript); }
                        let n = match read_uint(&script[index..], 2) {
                            Ok(n) => n,
                            Err(_) => { return Err(Error::EarlyEndOfScript); }
                        };
                        if script.len() < index + 2 + n { return Err(Error::EarlyEndOfScript); }
                        if executing {
                            stack.push_alloc(AbstractStackElem::new_raw(&script[index + 2..index + n + 2]));
                        }
                        index += 2 + n;
                    }
                    (_, opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4)) => {
                        let n = match read_uint(&script[index..], 4) {
                            Ok(n) => n,
                            Err(_) => { return Err(Error::EarlyEndOfScript); }
                        };
                        if script.len() < index + 4 + n { return Err(Error::EarlyEndOfScript); }
                        if executing {
                            stack.push_alloc(AbstractStackElem::new_raw(&script[index + 4..index + n + 4]));
                        }
                        index += 4 + n;
                    }
                    // If-statements take effect when not executing
                    (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_IF)) |
                    (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_NOTIF)) => exec_stack.push(false),
                    (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_ELSE)) => {
                        match exec_stack.last_mut() {
                            Some(ref_e) => { *ref_e = !*ref_e }
                            None => { return Err(Error::ElseWithoutIf); }
                        }
                    }
                    (false, opcodes::Class::Ordinary(opcodes::Ordinary::OP_ENDIF)) => {
                        if exec_stack.pop().is_none() {
                            return Err(Error::EndifWithoutIf);
                        }
                    }
                    // No-ops and non-executed operations do nothing
                    (true, opcodes::Class::NoOp) | (false, _) => {}
                    // Actual opcodes
                    (true, opcodes::Class::Ordinary(op)) => {
                        match op {
                            opcodes::Ordinary::OP_PUSHDATA1 | opcodes::Ordinary::OP_PUSHDATA2 | opcodes::Ordinary::OP_PUSHDATA4 => {
                                // handled above
                            }
                            opcodes::Ordinary::OP_IF => {
                                let top_bool = {
                                    let top = stack.peek_mut();
                                    top.bool_value()
                                };
                                match top_bool {
                                    None => {
                                        let mut stack_true = stack.clone();
                                        // Try pushing false and see what happens
                                        if stack.peek_mut().set_bool_value(false).is_ok() {
                                            if let Ok(res) = recurse(&script[index - 1..], stack, exec_stack.clone(), depth + 1) {
                                                return Ok(res);
                                            }
                                        }
                                        // Failing that, push true
                                        try!(stack_true.peek_mut().set_bool_value(true));
                                        return recurse(&script[index - 1..], stack_true, exec_stack, depth + 1);
                                    }
                                    Some(val) => {
                                        stack.pop();
                                        exec_stack.push(val)
                                    }
                                }
                            }
                            opcodes::Ordinary::OP_NOTIF => {
                                let top_bool = {
                                    let top = stack.peek_mut();
                                    top.bool_value()
                                };
                                match top_bool {
                                    None => {
                                        let mut stack_true = stack.clone();
                                        // Try pushing false and see what happens
                                        if stack.peek_mut().set_bool_value(false).is_ok() {
                                            if let Ok(res) = recurse(&script[index - 1..], stack, exec_stack.clone(), depth + 1) {
                                                return Ok(res);
                                            }
                                        }
                                        // Failing that, push true
                                        try!(stack_true.peek_mut().set_bool_value(true));
                                        return recurse(&script[index - 1..], stack_true, exec_stack, depth + 1);
                                    }
                                    Some(val) => {
                                        stack.pop();
                                        exec_stack.push(!val)
                                    }
                                }
                            }
                            opcodes::Ordinary::OP_ELSE => {
                                match exec_stack.last_mut() {
                                    Some(ref_e) => { *ref_e = !*ref_e }
                                    None => { return Err(Error::ElseWithoutIf); }
                                }
                            }
                            opcodes::Ordinary::OP_ENDIF => {
                                if exec_stack.pop().is_none() {
                                    return Err(Error::EndifWithoutIf);
                                }
                            }
                            opcodes::Ordinary::OP_VERIFY => op_verify_satisfy!(stack),
                            opcodes::Ordinary::OP_TOALTSTACK => { stack.top_to_altstack(); }
                            opcodes::Ordinary::OP_FROMALTSTACK => { try!(stack.top_from_altstack()); }
                            opcodes::Ordinary::OP_2DROP => stack_opcode!(stack: require 2; drop 1; drop 2),
                            opcodes::Ordinary::OP_2DUP  => stack_opcode!(stack: require 2; copy 2; copy 1),
                            opcodes::Ordinary::OP_3DUP  => stack_opcode!(stack: require 3; copy 3; copy 2; copy 1),
                            opcodes::Ordinary::OP_2OVER => stack_opcode!(stack: require 4; copy 4; copy 3),
                            opcodes::Ordinary::OP_2ROT  => stack_opcode!(stack: require 6;
                                                                                perm (1, 3, 5);
                                                                                perm (2, 4, 6)),
                            opcodes::Ordinary::OP_2SWAP => stack_opcode!(stack: require 4;
                                                                                swap (2, 4);
                                                                                swap (1, 3)),
                            opcodes::Ordinary::OP_DROP  => stack_opcode!(stack: require 1; drop 1),
                            opcodes::Ordinary::OP_DUP   => stack_opcode!(stack: require 1; copy 1),
                            opcodes::Ordinary::OP_NIP   => stack_opcode!(stack: require 2; drop 2),
                            opcodes::Ordinary::OP_OVER  => stack_opcode!(stack: require 2; copy 2),
                            opcodes::Ordinary::OP_PICK => {
                                let top_n = {
                                    let top = stack.peek_mut();
                                    try!(top.set_numeric());
                                    try!(top.set_num_lo(0));
                                    top.num_value().map(|n| n as usize)
                                };
                                stack.pop();
                                match top_n {
                                    Some(n) => stack_opcode!(stack: require (n + 1); copy (n + 1)),
                                    // The stack will wind up with the 1 and nth inputs being identical
                                    // with n input-dependent. I can imagine scripts which check this
                                    // condition or its negation for various n to get arbitrary finite
                                    // sets of allowable values. It's not clear to me that this is
                                    // feasible to analyze.
                                    None => { return Err(Error::Unanalyzable); }
                                }
                            }
                            opcodes::Ordinary::OP_ROLL => {
                                let top_n = {
                                    let top = stack.peek_mut();
                                    try!(top.set_numeric());
                                    try!(top.set_num_lo(0));
                                    top.num_value().map(|n| n as usize)
                                };
                                stack.pop();
                                match top_n {
                                    Some(n) => stack_opcode!(stack: require (n + 1); copy (n + 1); drop (n + 1)),
                                    // The stack will wind up reordered, so in principle I could just force
                                    // the input to be zero (other n values can be converted to zero by just
                                    // manually rearranging the input). The problem is if numeric bounds are
                                    // later set on n. I can't analyze that.
                                    None => { return Err(Error::Unanalyzable); }
                                }
                            }
                            opcodes::Ordinary::OP_ROT  => stack_opcode!(stack: require 3; perm (1, 2, 3)),
                            opcodes::Ordinary::OP_SWAP => stack_opcode!(stack: require 3; swap (1, 2)),
                            opcodes::Ordinary::OP_TUCK => stack_opcode!(stack: require 2; copy 2; copy 1; drop 2),
                            opcodes::Ordinary::OP_IFDUP => {
                                let top_bool = {
                                    let top = stack.peek_mut();
                                    top.bool_value()
                                };
                                match top_bool {
                                    Some(false) => { }
                                    Some(true) => { stack_opcode!(stack: require 1; copy 1); }
                                    None => {
                                        let mut stack_true = stack.clone();
                                        // Try pushing false and see what happens
                                        if stack.peek_mut().set_bool_value(false).is_ok() {
                                            if let Ok(res) = recurse(&script[index - 1..], stack, exec_stack.clone(), depth + 1) {
                                                return Ok(res);
                                            }
                                        }
                                        // Failing that, push true
                                        try!(stack_true.peek_mut().set_bool_value(true));
                                        return recurse(&script[index - 1..], stack_true, exec_stack, depth + 1);
                                    }
                                }
                            }
                            opcodes::Ordinary::OP_DEPTH => {
                                let len = stack.len() as i64;
                                let new_elem = stack.push_alloc(AbstractStackElem::new_unknown());
                                try!(new_elem.set_numeric());
                                try!(new_elem.set_num_lo(len));
                            }
                            opcodes::Ordinary::OP_SIZE => {
                                let top = stack.peek_index();
                                let new_elem = stack.push_alloc(AbstractStackElem::new_unknown());
                                try!(new_elem.set_numeric());
                                try!(new_elem.add_validator(Validator { args: vec![top],
                                                                        check: check::op_size,
                                                                        update: update::op_size }));
                            }
                            opcodes::Ordinary::OP_EQUAL => boolean_opcode_satisfy!(stack, binary op_equal),
                            opcodes::Ordinary::OP_EQUALVERIFY => {
                                boolean_opcode_satisfy!(stack, binary op_equal);
                                op_verify_satisfy!(stack);
                            }
                            opcodes::Ordinary::OP_NOT => boolean_opcode_satisfy!(stack, unary op_not),
                            opcodes::Ordinary::OP_0NOTEQUAL => boolean_opcode_satisfy!(stack, unary op_0notequal),
                            opcodes::Ordinary::OP_NUMEQUAL => boolean_opcode_satisfy!(stack, binary op_numequal),
                            opcodes::Ordinary::OP_NUMEQUALVERIFY => {
                                boolean_opcode_satisfy!(stack, binary op_numequal);
                                op_verify_satisfy!(stack);
                            }
                            opcodes::Ordinary::OP_NUMNOTEQUAL => boolean_opcode_satisfy!(stack, binary op_numnotequal),
                            opcodes::Ordinary::OP_LESSTHAN => boolean_opcode_satisfy!(stack, binary op_numlt),
                            opcodes::Ordinary::OP_GREATERTHAN => boolean_opcode_satisfy!(stack, binary op_numgt),
                            opcodes::Ordinary::OP_LESSTHANOREQUAL => boolean_opcode_satisfy!(stack, binary op_numlteq),
                            opcodes::Ordinary::OP_GREATERTHANOREQUAL => boolean_opcode_satisfy!(stack, binary op_numgteq),
                            opcodes::Ordinary::OP_1ADD | opcodes::Ordinary::OP_1SUB | opcodes::Ordinary::OP_NEGATE |
                            opcodes::Ordinary::OP_ABS | opcodes::Ordinary::OP_ADD | opcodes::Ordinary::OP_SUB |
                            opcodes::Ordinary::OP_BOOLAND | opcodes::Ordinary::OP_BOOLOR |
                            opcodes::Ordinary::OP_MIN | opcodes::Ordinary::OP_MAX | opcodes::Ordinary::OP_WITHIN => {
                                return Err(Error::Unanalyzable);
                            }
                            opcodes::Ordinary::OP_RIPEMD160 => unary_opcode_satisfy!(stack, op_ripemd160),
                            opcodes::Ordinary::OP_SHA1 => unary_opcode_satisfy!(stack, op_sha1),
                            opcodes::Ordinary::OP_SHA256 => unary_opcode_satisfy!(stack, op_sha256),
                            opcodes::Ordinary::OP_HASH160 => unary_opcode_satisfy!(stack, op_hash160),
                            opcodes::Ordinary::OP_HASH256 => unary_opcode_satisfy!(stack, op_hash256),
                            // Ignore code separators since we don't check signatures
                            opcodes::Ordinary::OP_CODESEPARATOR => {}
                            opcodes::Ordinary::OP_CHECKSIG => boolean_opcode_satisfy!(stack, binary op_checksig),
                            opcodes::Ordinary::OP_CHECKSIGVERIFY => {
                                boolean_opcode_satisfy!(stack, binary op_checksig);
                                op_verify_satisfy!(stack);
                            }
                            opcodes::Ordinary::OP_CHECKMULTISIG | opcodes::Ordinary::OP_CHECKMULTISIGVERIFY => {
                                let (n_keys, n_keys_hi) = {
                                    let elem = stack.pop_mut();
                                    try!(elem.set_numeric());
                                    try!(elem.set_num_lo(0));
                                    try!(elem.set_num_hi(20));
                                    (elem.num_lo(), elem.num_hi())
                                };
                                let mut allowable_failures: i64 = 0;
                                for _ in 0..n_keys {
                                    let key = stack.pop_mut();
                                    if key.may_be_pubkey() {
                                        allowable_failures += 1;
                                    }
                                }
                                if n_keys == n_keys_hi {
                                    let (n_sigs, n_sigs_hi) = {
                                        let elem = stack.pop_mut();
                                        try!(elem.set_numeric());
                                        try!(elem.set_num_lo(0));
                                        try!(elem.set_num_hi(n_keys));
                                        (elem.num_lo(), elem.num_hi())
                                    };
                                    allowable_failures -= n_sigs;
                                    for _ in 0..n_sigs {
                                        let sig = stack.pop_mut();
                                        if !sig.may_be_signature() {
                                            allowable_failures -= 1;
                                        }
                                        if allowable_failures < 0 {
                                            return Err(Error::Unsatisfiable);
                                        }
                                        if n_sigs != n_sigs_hi { return Err(Error::Unanalyzable); }
                                    }
                                } else { return Err(Error::Unanalyzable); }
                                // Successful multisig, push an unknown boolean
                                {
                                    let result = stack.push_alloc(AbstractStackElem::new_unknown());
                                    try!(result.set_boolean())
                                }

                                // If it's a VERIFY op, assume it passed and carry on
                                if op == opcodes::Ordinary::OP_CHECKMULTISIGVERIFY {
                                    op_verify_satisfy!(stack);
                                }
                            }
                        }
                    }
                }
            }
            // If we finished, we are only unspendable if we have false on the stack
            match stack.peek_mut().bool_value() {
                None => stack.peek_mut().set_bool_value(true).map(|_| stack.build_initial_stack()),
                Some(true) => Ok(stack.build_initial_stack()),
                Some(false) => Err(Error::Unsatisfiable)
            }
        }

        recurse(&self.0, AbstractStack::new(), vec![], 1)
    }
}

impl Default for Script {
    fn default() -> Script { Script(vec![].into_boxed_slice()) }
}

/// Creates a new script from an existing vector
impl From<Vec<u8>> for Script {
    fn from(v: Vec<u8>) -> Script { Script(v.into_boxed_slice()) }
}

impl_index_newtype!(Script, u8);

/// A "parsed opcode" which allows iterating over a Script in a more sensible way
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Instruction<'a> {
    /// Push a bunch of data
    PushBytes(&'a [u8]),
    /// Some non-push opcode
    Op(opcodes::All),
    /// An opcode we were unable to parse
    Error(Error)
}

/// Iterator over a script returning parsed opcodes
pub struct Instructions<'a> {
    data: &'a [u8]
}

impl<'a> IntoIterator for &'a Script {
    type Item = Instruction<'a>;
    type IntoIter = Instructions<'a>;
    fn into_iter(self) -> Instructions<'a> { Instructions { data: &self.0[..] } }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Instruction<'a>> {
        if self.data.is_empty() {
            return None;
        }

        match opcodes::All::from(self.data[0]).classify() {
            opcodes::Class::PushBytes(n) => {
                let n = n as usize;
                if self.data.len() < n + 1 {
                    return Some(Instruction::Error(Error::EarlyEndOfScript));
                }
                let ret = Some(Instruction::PushBytes(&self.data[1..n+1]));
                self.data = &self.data[n + 1..];
                ret
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => {
                if self.data.len() < 2 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let n = match read_uint(&self.data[1..], 1) {
                    Ok(n) => n,
                    Err(e) => { return Some(Instruction::Error(e)); }
                };
                if self.data.len() < n + 2 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let ret = Some(Instruction::PushBytes(&self.data[2..n+2]));
                self.data = &self.data[n + 2..];
                ret
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => {
                if self.data.len() < 3 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let n = match read_uint(&self.data[1..], 2) {
                    Ok(n) => n,
                    Err(e) => { return Some(Instruction::Error(e)); }
                };
                if self.data.len() < n + 3 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let ret = Some(Instruction::PushBytes(&self.data[3..n + 3]));
                self.data = &self.data[n + 3..];
                ret
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => {
                if self.data.len() < 5 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let n = match read_uint(&self.data[1..], 4) {
                    Ok(n) => n,
                    Err(e) => { return Some(Instruction::Error(e)); }
                };
                if self.data.len() < n + 5 { return Some(Instruction::Error(Error::EarlyEndOfScript)); }
                let ret = Some(Instruction::PushBytes(&self.data[5..n + 5]));
                self.data = &self.data[n + 5..];
                ret
            }
            // Everything else we can push right through
            _ => {
                let ret = Some(Instruction::Op(opcodes::All::from(self.data[0])));
                self.data = &self.data[1..];
                ret
            }
        }
    }
}

impl Builder {
    /// Creates a new empty script
    pub fn new() -> Builder { Builder(vec![]) }

    /// The length in bytes of the script
    pub fn len(&self) -> usize { self.0.len() }

    /// Whether the script is the empty script
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack. Integers are
    /// encoded as little-endian signed-magnitude numbers, but there are
    /// dedicated opcodes to push some small integers.
    pub fn push_int(mut self, data: i64) -> Builder {
        // We can special-case -1, 1-16
        if data == -1 || (data >= 1 && data <= 16) {
            self.0.push((data - 1 + opcodes::OP_TRUE as i64) as u8);
            self
        }
        // We can also special-case zero
        else if data == 0 {
            self.0.push(opcodes::OP_FALSE as u8);
            self
        }
        // Otherwise encode it as data
        else { self.push_scriptint(data) }
    }

    /// Adds instructions to push an integer onto the stack, using the explicit
    /// encoding regardless of the availability of dedicated opcodes.
    pub fn push_scriptint(self, data: i64) -> Builder {
        self.push_slice(&build_scriptint(data))
    }

    /// Adds instructions to push some arbitrary data onto the stack
    pub fn push_slice(mut self, data: &[u8]) -> Builder {
        // Start with a PUSH opcode
        match data.len() {
            n if n < opcodes::Ordinary::OP_PUSHDATA1 as usize => { self.0.push(n as u8); },
            n if n < 0x100 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA1 as u8);
                self.0.push(n as u8);
            },
            n if n < 0x10000 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA2 as u8);
                self.0.push((n % 0x100) as u8);
                self.0.push((n / 0x100) as u8);
            },
            n if n < 0x100000000 => {
                self.0.push(opcodes::Ordinary::OP_PUSHDATA4 as u8);
                self.0.push((n % 0x100) as u8);
                self.0.push(((n / 0x100) % 0x100) as u8);
                self.0.push(((n / 0x10000) % 0x100) as u8);
                self.0.push((n / 0x1000000) as u8);
            }
            _ => panic!("tried to put a 4bn+ sized object into a script!")
        }
        // Then push the acraw
        self.0.extend(data.iter().cloned());
        self
    }

    /// Adds a single opcode to the script
    pub fn push_opcode(mut self, data: opcodes::All) -> Builder {
        self.0.push(data as u8);
        self
    }

    /// Converts the `Builder` into an unmodifiable `Script`
    pub fn into_script(self) -> Script {
        Script(self.0.into_boxed_slice())
    }
}

/// Adds an individual opcode to the script
impl Default for Builder {
    fn default() -> Builder { Builder(vec![]) }
}

/// Creates a new script from an existing vector
impl From<Vec<u8>> for Builder {
    fn from(v: Vec<u8>) -> Builder { Builder(v) }
}

impl_index_newtype!(Builder, u8);

// User-facing serialization
impl serde::Serialize for Script {
    fn serialize<S>(&self, s: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer,
    {
        s.visit_str(&format!("{:x}", self))
    }
}

impl serde::Deserialize for Script {
    fn deserialize<D>(d: &mut D) -> Result<Script, D::Error>
        where D: serde::Deserializer
    {
        use serialize::hex::FromHex;

        struct ScriptVisitor;
        impl serde::de::Visitor for ScriptVisitor {
            type Value = Script;

            fn visit_string<E>(&mut self, v: String) -> Result<Script, E>
                where E: serde::de::Error
            {
                self.visit_str(&v)
            }

            fn visit_str<E>(&mut self, hex_str: &str) -> Result<Script, E>
                where E: serde::de::Error
            {
                let raw_vec: Vec<u8> = try!(hex_str.from_hex()
                                                   .map_err(|_| serde::de::Error::syntax("bad script hex")));
                Ok(Script::from(raw_vec))
            }
        }

        d.visit(ScriptVisitor)
    }
}

// Network serialization
impl<S: SimpleEncoder> ConsensusEncodable<S> for Script {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        self.0.consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Script {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Script, D::Error> {
        Ok(Script(try!(ConsensusDecodable::consensus_decode(d))))
    }
}

/// A trace of a transaction input's script execution
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct InputTrace {
    input_txid: Sha256dHash,
    input_vout: usize,
    sig_trace: ScriptTrace,
    pubkey_trace: Option<ScriptTrace>,
    p2sh_trace: Option<ScriptTrace>,
    error: Option<Error>
}

/// A trace of a transaction's execution
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TransactionTrace {
    txid: Sha256dHash,
    inputs: Vec<InputTrace>
}

#[cfg(test)]
mod test {
    use secp256k1::Secp256k1;
    use serialize::hex::FromHex;

    use super::*;
    use super::build_scriptint;
    use super::MaybeOwned::Owned;

    use network::serialize::{deserialize, serialize};
    use blockdata::opcodes;
    use blockdata::transaction::Transaction;

    fn test_tx(tx_hex: &'static str, output_hex: Vec<&'static str>) {
        let s = Secp256k1::new();
        let tx_hex = tx_hex.from_hex().unwrap();

        let tx: Transaction = deserialize(&tx_hex).ok().expect("transaction");
        let script_pk: Vec<Script> = output_hex.iter()
                                                .map(|hex| format!("{:02x}{}", hex.len() / 2, hex))
                                                .map(|hex| (&hex[..]).from_hex().unwrap())
                                                .map(|hex| deserialize(&hex)
                                                .ok()
                                                .expect("scriptpk"))
                                                .collect();

        for (n, script) in script_pk.iter().enumerate() {
            let mut stack = vec![];
            assert_eq!(tx.input[n].script_sig.evaluate(&s, &mut stack, Some((&tx, n)), None), Ok(()));
            assert_eq!(script.evaluate(&s, &mut stack, Some((&tx, n)), None), Ok(()));
            assert!(stack.len() >= 1);
            assert_eq!(read_scriptbool(&stack.pop().unwrap()[..]), true);
            for instruction in (&script).into_iter() {
                if let Instruction::Error(_) = instruction {
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn script() {
        let mut comp = vec![];
        let mut script = Builder::new();
        assert_eq!(&script[..], &comp[..]);

        // small ints
        script = script.push_int(1);  comp.push(81u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(0);  comp.push(0u8);  assert_eq!(&script[..], &comp[..]);
        script = script.push_int(4);  comp.push(84u8); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-1); comp.push(79u8); assert_eq!(&script[..], &comp[..]);
        // forced scriptint
        script = script.push_scriptint(4); comp.extend([1u8, 4].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // big ints
        script = script.push_int(17); comp.extend([1u8, 17].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(10000); comp.extend([2u8, 16, 39].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        // notice the sign bit set here, hence the extra zero/128 at the end
        script = script.push_int(10000000); comp.extend([4u8, 128, 150, 152, 0].iter().cloned()); assert_eq!(&script[..], &comp[..]);
        script = script.push_int(-10000000); comp.extend([4u8, 128, 150, 152, 128].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // data
        script = script.push_slice("NRA4VR".as_bytes()); comp.extend([6u8, 78, 82, 65, 52, 86, 82].iter().cloned()); assert_eq!(&script[..], &comp[..]);

        // opcodes 
        script = script.push_opcode(opcodes::All::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
        script = script.push_opcode(opcodes::All::OP_CHECKSIG); comp.push(0xACu8); assert_eq!(&script[..], &comp[..]);
    }

    #[test]
    fn script_builder() {
        // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
        let script = Builder::new().push_opcode(opcodes::All::OP_DUP)
                                   .push_opcode(opcodes::All::OP_HASH160)
                                   .push_slice(&"16e1ae70ff0fa102905d4af297f6912bda6cce19".from_hex().unwrap())
                                   .push_opcode(opcodes::All::OP_EQUALVERIFY)
                                   .push_opcode(opcodes::All::OP_CHECKSIG)
                                   .into_script();
        assert_eq!(&format!("{:x}", script), "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac");
    }

    #[test]
    fn script_serialize() {
        let hex_script = "6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52".from_hex().unwrap();
        let script: Result<Script, _> = deserialize(&hex_script);
        assert!(script.is_ok());
        assert_eq!(serialize(&script.unwrap()).ok(), Some(hex_script));
    }

    #[test]
    fn scriptint_round_trip() {
        assert_eq!(build_scriptint(-1), vec![0x81]);
        assert_eq!(build_scriptint(255), vec![255, 0]);
        assert_eq!(build_scriptint(256), vec![0, 1]);
        assert_eq!(build_scriptint(257), vec![1, 1]);
        assert_eq!(build_scriptint(511), vec![255, 1]);
        for &i in [10, 100, 255, 256, 1000, 10000, 25000, 200000, 5000000, 1000000000,
                             (1 << 31) - 1, -((1 << 31) - 1)].iter() {
            assert_eq!(Ok(i), read_scriptint(&build_scriptint(i)));
            assert_eq!(Ok(-i), read_scriptint(&build_scriptint(-i)));
        }
        assert!(read_scriptint(&build_scriptint(1 << 31)).is_err());
        assert!(read_scriptint(&build_scriptint(-(1 << 31))).is_err());
    }

    #[test]
    fn script_eval_simple() {
        let s = Secp256k1::new();
        let mut script = Builder::new();
        assert!(script.clone().into_script().evaluate(&s, &mut vec![], None, None).is_ok());

        script = script.push_opcode(opcodes::All::OP_RETURN);
        assert!(script.clone().into_script().evaluate(&s, &mut vec![], None, None).is_err());
    }

    #[test]
    fn script_eval_checksig_without_tx() {
        let s = Secp256k1::new();
        let hex_pk = "1976a914e729dea4a3a81108e16376d1cc329c91db58999488ac".from_hex().unwrap();
        let script_pk: Script = deserialize(&hex_pk).ok().expect("scriptpk");
        // Should be able to check that the sig is there and pk correct
        // before needing a transaction
        assert_eq!(script_pk.evaluate(&s, &mut vec![], None, None), Err(Error::PopEmptyStack));
        assert_eq!(script_pk.evaluate(&s, &mut vec![Owned(vec![]), Owned(vec![])], None, None),
                                                                    Err(Error::EqualVerifyFailed("e729dea4a3a81108e16376d1cc329c91db589994".to_owned(),
                                                                                                 "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb".to_owned())));
        // But if the signature is there, we need a tx to check it
        assert_eq!(script_pk.evaluate(&s, &mut vec![Owned(vec![]), Owned("026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a".from_hex().unwrap())], None, None), Err(Error::NoTransaction));
        assert_eq!(script_pk.evaluate(&s, &mut vec![Owned(vec![0]), Owned("026d5d4cfef5f3d97d2263941b4d8e7aaa82910bf8e6f7c6cf1d8f0d755b9d2d1a".from_hex().unwrap())], None, None), Err(Error::NoTransaction));
    }

    #[test]
    fn script_eval_pubkeyhash() {
        let s = Secp256k1::new();

        // nb these are both prefixed with their length in 1 byte
        let tx_hex = "010000000125d6681b797691aebba34b9d8e50f769ab1e8807e78405ae505c218cf8e1e9e1a20100006a47304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c0121029fa8e8d8e3fd61183ab52f98d65500fd028a5d0a899c6bcd4ecaf1eda9eac284ffffffff0110270000000000001976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac00000000".from_hex().unwrap();

        let output_hex = "1976a914299567077f41bc20059dc21a1eb1ef5a6a43b9c088ac".from_hex().unwrap();

        let tx: Transaction = deserialize(&tx_hex).ok().expect("transaction");
        let script_pk: Script = deserialize(&output_hex).ok().expect("scriptpk");

        let mut stack = vec![];
        assert_eq!(tx.input[0].script_sig.evaluate(&s, &mut stack, None, None), Ok(()));
        assert_eq!(script_pk.evaluate(&s, &mut stack, Some((&tx, 0)), None), Ok(()));
        assert_eq!(stack.len(), 1);
        assert_eq!(read_scriptbool(&stack.pop().unwrap()[..]), true);
    }


    #[test]
    fn script_eval_testnet_failure_1() {
        // OP_PUSHNUM ops weren't correct, also computed zero must be [], not [0]
        // txid dc3aad51b4b9ea1ef40755a38b0b4d6e08c72d2ac5e95b8bebe9bd319b6aed7e
        test_tx(
            "010000000560e0b5061b08a60911c9b2702cc0eba80adbe42f3ec9885c76930837db5380c001000000054f01e40164ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b959000000000351519bffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b959020000000452018293ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b95903000000045b5a5193ffffffff0d2fe5749c96f15e37ceed29002c7f338df4f2781dd79f4d4eea7a08aa69b95904000000045b5a5193ffffffff06002d310100000000029f91002d3101000000000401908f87002d31010000000001a0002d3101000000000705feffffff808730d39700000000001976a9140467f85e06a2ef0a479333b47258f4196fb94b2c88ac002d3101000000000604ffffff7f9c00000000",
            vec!["a5", "61", "0087", "9c", "9d51"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_2() {
        // OP_PUSHDATA2 must read its length little-endian
        // txid c5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7)
        test_tx(
            "010000003422300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560300000006011601150114ffffffff22300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560400000006011601150114ffffffff22300a976c1f0f6bd6172ded8cb76c23f6e57d3b19e9ff1f403990e70acf19560900000006050000008000ffffffff42e9e966f8c293ad44c0b726ec85c5338d1f30cee63aedfb6ead49571477f22909000000020051ffffffff42e9e966f8c293ad44c0b726ec85c5338d1f30cee63aedfb6ead49571477f2290a000000034f00a3ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f030000000151ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f040000000451525355ffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f0500000003016f8cffffffff4f0ccb5158e5497900b7563c5e0ab7fad5e169b9f46e8ca24c84b1f2dc91911f09000000025d5effffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a0400000005016f5a5193ffffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a06000000065a005b6b756cffffffff5649f4d40acc1720997749ede3abb24105e637dd309fb3deee4a49c49d3b4f1a080000000100ffffffff67e36cd8a0a57458261704363fc21ce927b8214b381bcf86c0b6bd8f23e5e70c0100000006011601150114ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d6537040000000704ffffff7f7693ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d6537050000001b1a6162636465666768696a6b6c6d6e6f707172737475767778797affffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d653708000000044d010008ffffffff6ded57e5e632ec542b8ab851df40400c32052ce2b999cf2c6c1352872c5d65370a000000025191ffffffff6f3c0204703766775324115c32fd121a16f0df64f0336490157ebd94b62e059e02000000020075ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e0295020100000006016f51935c94ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e029502020000000403008000ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e029502060000001b1a6162636465666768696a6b6c6d6e6f707172737475767778797affffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e02950207000000044f005152ffffffff8f339185bdf4c571055114df3cbbb9ebfa31b605b99c4088a1b226f88e0295020a00000003515193ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a330300000000025100ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a33030500000006011601150114ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a3303080000000100ffffffff925f27a4db9032976b0ed323094dcfd12d521f36f5b64f4879a20750729a33030a00000002010bffffffffadb5b4d9c20de237a2bfa5543d8d53546fdeffed9b114e307b4d6823ef5fcd2203000000014fffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe010000000100ffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe0300000006011601150114ffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe050000000351009affffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe060000000403ffff7fffffffffb1ecb9e79ce8f54e8529feeeb668a72a7f0c49831f83d76cfbc83155b8b9e1fe090000000351009bffffffffb8870d0eb7a246fe332401c2f44c59417d56b30de2640514add2e54132cf4bad0200000006011601150114ffffffffb8870d0eb7a246fe332401c2f44c59417d56b30de2640514add2e54132cf4bad04000000045b5a5193ffffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a010000000151ffffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a08000000025d5effffffffc162c5adb8f1675ad3a17b417076efc8495541bcb1cd0f11755f062fb49d1a7a0a000000045b5a5193ffffffffcc68b898c71166468049c9a4130809555908c30f3c88c07e6d28d2f6a6bb486b06000000020051ffffffffcc68b898c71166468049c9a4130809555908c30f3c88c07e6d28d2f6a6bb486b0800000003028000ffffffffce1cba7787ec167235879ca17f46bd4bfa405f9e3e2e35c544537bbd65a5d9620100000006011601150114ffffffffce1cba7787ec167235879ca17f46bd4bfa405f9e3e2e35c544537bbd65a5d962030000000704ffffff7f7693ffffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb5829010000000100ffffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb582907000000025d5effffffffd6bb18a96b21035e2d04fcd54f2f503d199aeb86b8033535e06ffdb400fb582909000000025b5affffffffd878941d1968d5027129e4b462aead4680bcce392c099d50f294063a528dad9c030000000161ffffffffd878941d1968d5027129e4b462aead4680bcce392c099d50f294063a528dad9c06000000034f4f93ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a0200000006011601150114ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a0300000003016f92ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a050000000704ffffff7f7693ffffffffe7ea17c77cbad48a8caa6ca87749ef887858eb3becc55c65f16733837ad5043a08000000025173fffffffff24629f6d9f2b7753e1b6fe1104f8554de1ce6be0dfb4f262a28c38587ed5b34060000000151ffffffff0290051000000000001976a914954659bcb93fdad012a00d825a9bce69dc7c6a2688ac800c49110000000008517a01158874528700000000",
            vec![
                "5279011688745387",
                "007a011488745287",
                "825587",
                "77",
                "4f9c",
                "76636768",
                "709393588893935687",
                "016e87",
                "6e7b8887",
                "9e",
                "93011587",
                "6362675168",
                "517a011588745287",
                "05feffffff0087",
                "82011a87",
                "6301ba675168",
                "0087",
                // There are 35 more ..
            ]
        );
    }

    #[test]
    fn script_eval_testnet_failure_3() {
        // For SIGHASH_SINGLE signatures, the unsigned txouts are null, that is,
        // have blank script and value **** (u64)-1 *****
        // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
        test_tx(
            "01000000062c4fb29a89bfe568586dd52c4db39c3daed014bce2d94f66d79dadb82bd83000000000004847304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f01ffffffff5b1015187325285e42c022e0c8388c0bd00a7efb0b28cd0828a5e9575bc040010000000049483045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a81ffffffffc0e15d72865802279f4f5cd13fc86749ce27aac9fd4ba5a8b57c973a82d04a01000000004a493046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4502ffffffff4a1b2b51da86ee82eadce5d3b852aa8f9b3e63106d877e129c5cf450b47f5c02000000004a493046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db182ffffffff61a3e0d8305112ea97d9a2c29b258bd047cf7169c70b4136ba66feffee680f030000000049483045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a6003ffffffffc7d6933e5149568d8b77fbd3f88c63e4e2449635c22defe02679492e7cb926030000000048473044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf83ffffffff0700e1f505000000001976a914c311d13cfbaa1fc8d364a8e89feb1985de58ae3988ac80d1f008000000001976a914eb907923b86af59d3fd918478546c7a234586caf88ac00c2eb0b000000001976a9141c88b9d44e5fc327025157c75af73774758ba68088ac80b2e60e000000001976a914142c0947df1df159b2367a0e1328efb5b76b62bd88ac00a3e111000000001976a914616bffc03acbb416ccf76a048a9bbb974c0504c488ac8093dc14000000001976a9141d5e6e993d168384864c3a92216b9b77560d436488ac804eacab060000001976a914aa9da4a3a4ddc7398ae467eddaf80d743349d6e988ac00000000",
            vec![
                "2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac",
                "2102f71546fc597e63e2a72dadeeeb50c0ca64079a5a530cb01dd939716d41e9d480ac",
                "21031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43ac",
                "210249c6a76e37c2fcd56687dde6b75bbdf72fcdeeab6fe81561a9c41ac90d9d1f48ac",
                "21035c100972ff8c572dc80eaa15a958ab99064d7c6b9e55f0e6408dec11edd4debbac",
                "2103837725cf7377d40a965f082fa6a942d39d9c2433c6d3c7bb4fa262e7d0d19defac",
            ]
        );
    }

    #[test]
    fn script_eval_testnet_failure_4() {
        // Multisig
        // txid 067cb44dcbd1e3b16eed2482cbe462a461896d4eec891935020a97158f1c100b
        test_tx(
            "01000000018feacff32dfee2218f7873c11087c65b5e7890ad2395da7d4a3e9a7b77bd23f8000000009300483045022100f76f485db0632f4a7fb3c95a5c0eae7b5d0e885f87ac4991e429b3c0f3c444ad0220155a281d7d9bb13ad013df8057a3d43f45de2702ba10b976164fbfcd4be452db014830450221008aa307b332eb0c96bf7c25c7d3c04ae75f071ed652f18dac55dedec7262aef6702203f0a46856b8b9acfac475f1056f04bf50e41aa967c401b85bea3ef20e470d27501ffffffff0100f2052a010000001976a9140550f9aedabdd2ee0424f53f26faeff1b899cc1688ac00000000",
            vec!["52210266816de738c62ad789119fdb13131faa13f588359484ca61d0515cdcc7648ecd21025fe4a325d96f109529734af5de80b961274de5720c30646c398202e5d555adca52ae"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_5() {
        // Pushes in the dead half of OP_IF's should still skip over all the data (OP_PUSH[0..75]
        // txid 4d0bbf6348726a49600171033e456548a09b246829d649e77b929caf242ae6e7
        test_tx(
            "01000000017c19a5b0b84188bca5decac0dc8582f5f5ff003b1a4d705181ec5d9620c1f64600000000940048304502207d02ce76875b1b3f2b7af9e45954af1ab531da6ab3edd471aa9148f139c8bad1022100f0f85fd987e90a131f2e311acdfe212925e218ffa5cf79e84e9890c2ddbdbd450148304502207d02ce76875b1b3f2b7af9e45954af1ab531da6ab3edd471aa9148f139c8bad1022100f0f85fd987e90a131f2e311acdfe212925e218ffa5cf79e84e9890c2ddbdbd450151ffffffff0100e1f505000000001976a91403efb01790d098aef3752449a94a1dc593e527cd88ac00000000",
            vec!["6352210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02ef210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02ef52ae67a820080af0b0156c5dd12c820b2b1b4fbfa315d05ac5a0ea2f9a657d4c8881d0869f88a820080af0b0156c5dd12c820b2b1b4fbfa315d05ac5a0ea2f9a657d4c8881d0869f88210261411d0de63460bfed73cb871f868bc3064d1db2a09f27b2477852b1811a02efac68"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_6() {
        // Pushes in the dead half of OP_IF's should still skip over all the data (OP_PUSHDATA1 2 4)
        // txid a2119ab5f90270836643665183b21e114daaa6dfdc1bdd7525e1187aa153a229
        test_tx(
            "01000000015e0767f6b58b766d922c6ddd6afc46af9d21c613754bd7cb8010adf0c9c090d2010000000401010100ffffffff0180f0fa02000000001976a914993bcb95575ecda9e7106a30f42232b8e89917c388ac00000000",
            vec!["63ff4c0778657274726f7668"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_7() {
        // script_find_and_delete needs to drop the entire push operation, not just the signature data
        // txid 2c63aa814701cef5dbd4bbaddab3fea9117028f2434dddcdab8339141e9b14d1
        test_tx(
            "01000000022f196cf1e5bd426a04f07b882c893b5b5edebad67da6eb50f066c372ed736d5f000000006a47304402201f81ac31b52cb4b1ceb83f97d18476f7339b74f4eecd1a32c251d4c3cccfffa402203c9143c18810ce072969e4132fdab91408816c96b423b2be38eec8a3582ade36012102aa5a2b334bd8f135f11bc5c477bf6307ff98ed52d3ed10f857d5c89adf5b02beffffffffff8755f073f1170c0d519457ffc4acaa7cb2988148163b5dc457fae0fe42aa19000000009200483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a530347304402206da827fb26e569eb740641f9c1a7121ee59141703cbe0f903a22cc7d9a7ec7ac02204729f989b5348b3669ab020b8c4af01acc4deaba7c0d9f8fa9e06b2106cbbfeb01ffffffff010000000000000000016a00000000",
            vec![
                "76a91419660c27383b347112e92caba64fb1d07e9f63bf88ac",
                "483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53037552210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7152ae"
            ]
        );
    }

    #[test]
    fn script_eval_testnet_failure_8() {
        // Fencepost error in OP_CODESEPARATOR
        // txid 46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa
        test_tx(
            "01000000012432b60dc72cebc1a27ce0969c0989c895bdd9e62e8234839117f8fc32d17fbc000000004a493046022100a576b52051962c25e642c0fd3d77ee6c92487048e5d90818bcf5b51abaccd7900221008204f8fb121be4ec3b24483b1f92d89b1b0548513a134e345c5442e86e8617a501ffffffff010000000000000000016a00000000",
            vec!["24ab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_9() {
        // All OP_CODESEPARATORS must be removed, not just the first one
        // txid 6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190
        test_tx(
            "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a900000000924830450221009c0a27f886a1d8cb87f6f595fbc3163d28f7a81ec3c4b252ee7f3ac77fd13ffa02203caa8dfa09713c8c4d7ef575c75ed97812072405d932bd11e6a1593a98b679370148304502201e3861ef39a526406bad1e20ecad06be7375ad40ddb582c9be42d26c3a0d7b240221009d0a3985e96522e59635d19cc4448547477396ce0ef17a58e7d74c3ef464292301ffffffff010000000000000000016a00000000",
            vec!["21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041adab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041adab51"]
        );
    }

    #[test]
    fn script_eval_testnet_failure_10() {
        // In first 500 blocks, started failing after mem changes
        // txid a44d40b3a14aca3f19ccf47244ef4a70ed02d00f5d840c38756368e9a7cc24b1
        test_tx(
            "010000000328ce10c7189026866bcfc1d06b278981ddf21ec0e364e28e294365b5c328cd4301000000fd460100493046022100a78f180f5851ebe9de7e6ae6f88ecf36ed9f165e5df1e17eec16b22e6397dc0b022100c3ae88400294ae464665d63b8035f1de4bb19ddd7cc0cc5c1d5a3fe28f4fcae70147304402206f035ce436fa307038bf4bac15a8b97fadb3c809b6d9289eae7de0d0f9d527b1022026534d695be2d7adbebda5d2c4cdee83e27015eed32a5ff950ecf136a1db85760147304402201a0a6ac0f488e7dc8fc7c9aca5d79b541d60d7ad1aaf61f55ee57e61ff2dab4a02200267bfcce527810d7af54a30ebfb0ced371aa24bf7791ee72474c5ff5703d352014c69532102ca2a810ab17249b6033a038de563983881b4069270183f3c0aba945653e442162103f480f1b648d0d5167804ad4d586e0e757cc33fde0e133fd036e45d60d2db59e12103c18131d8de99d45fb72a774cab0ccc258cd2abd9605610da20b9a232c88a3cb653aeffffffff7ae001aef566f8273a7cd14dcbc1d2bcd7927de792c5042375033991ef5523c301000000fdfe0000483045022100b48f165ae0931a540a5d2151ea9408a551122dbae07ba4fe26b2d840d8812ae002207cc87346c2dea3ad287395176d15a96396141fb1b1bdaabba9dbf346506f601501483045022026f2db95286e9831c2efc60c2a65c3e4928a5fa9f045561540f689d8de856221022100aecd777e17b07eef046d40046da0b90fcea86938b21479ab0ef0d158ab8639dc014c69522102ca2a810ab17249b6033a038de563983881b4069270183f3c0aba945653e442162103f480f1b648d0d5167804ad4d586e0e757cc33fde0e133fd036e45d60d2db59e12103c18131d8de99d45fb72a774cab0ccc258cd2abd9605610da20b9a232c88a3cb653aeffffffffa51be37aee4c76f23461168ee6d82dba07181b318390625b9acb2ec2be1004ba01000000dc00483045022100e4a2e8db8d020fc15ec83961820f021bcedc748075e5b4985eebfa006dec14ec022016ea51461beac82c7aef059a8359015286672963fa571fc3f98497ee3303b374014930460221008e6d8d560e3bd8eae2af62e90cd3439d80f68e4c45327c16d98a445c8ff941aa022100d39bee0fff226c264047264dbb421bf378362c8930bf4463bb09ef1b4fdf8a720147522102ca2a810ab17249b6033a038de563983881b4069270183f3c0aba945653e442162103f480f1b648d0d5167804ad4d586e0e757cc33fde0e133fd036e45d60d2db59e152aeffffffff05c0caad2a0100000017a9141d9ca71efa36d814424ea6ca1437e67287aebe3487c09448660100000017a91424fbc77cdc62702ade74dcf989c15e5d3f9240bc87c05ee3a10100000017a914afbfb74ee994c7d45f6698738bc4226d065266f7876043993b000000001976a914d2a37ce20ac9ec4f15dd05a7c6e8e9fbdb99850e88ac00f2052a010000001976a9146b2044146a4438e6e5bfbc65f147afeb64d14fbb88ac00000000",
            vec![
                "a9149eb21980dc9d413d8eac27314938b9da920ee53e87",
                "a91409f70b896169c37981d2b54b371df0d81a136a2c87",
                "a914e371782582a4addb541362c55565d2cdf56f649887",
            ]
        );
    }

    macro_rules! hex_script (($s:expr) => (Script::from($s.from_hex().unwrap())));

    #[test]
    fn provably_unspendable_test() {
        // p2pk
        assert_eq!(hex_script!("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").is_provably_unspendable(), false);
        assert_eq!(hex_script!("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").is_provably_unspendable(), false);
        // p2pkhash
        assert_eq!(hex_script!("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac").is_provably_unspendable(), false);
        assert_eq!(hex_script!("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87").is_provably_unspendable(), true);
        // if return; else return
        assert_eq!(hex_script!("636a676a68").is_provably_unspendable(), true);
        // if return; else don't
        assert_eq!(hex_script!("636a6768").is_provably_unspendable(), false);
        // op_equal
        assert_eq!(hex_script!("87").is_provably_unspendable(), false);
        assert_eq!(hex_script!("000087").is_provably_unspendable(), false);
        assert_eq!(hex_script!("510087").is_provably_unspendable(), true);
        assert_eq!(hex_script!("510088").is_provably_unspendable(), true);
        // nested ifs
        assert_eq!(hex_script!("6363636363686868686800").is_provably_unspendable(), true);
        // repeated op_equals
        assert_eq!(hex_script!("8787878787878787").is_provably_unspendable(), false);
        // op_ifdup
        assert_eq!(hex_script!("73").is_provably_unspendable(), false);
        assert_eq!(hex_script!("5173").is_provably_unspendable(), false);
        assert_eq!(hex_script!("0073").is_provably_unspendable(), true);
        // this is honest to god tx e411dbebd2f7d64dafeef9b14b5c59ec60c36779d43f850e5e347abee1e1a455 on mainnet
        assert_eq!(hex_script!("76a9144838a081d73cf134e8ff9cfd4015406c73beceb388acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac").is_provably_unspendable(), true);
        // Real, testnet spent ones that caused me trouble
        assert_eq!(hex_script!("7c51880087").is_provably_unspendable(), false);
        assert_eq!(hex_script!("9e91").is_provably_unspendable(), false);
        assert_eq!(hex_script!("76a97ca8a687").is_provably_unspendable(), false);
        assert_eq!(hex_script!("04010203047576a914bfbd43270c1e824c01e27386844d062d2f7518a688ad76a97614d2f7b8a37fb9b46782534078f9748f41d61a22f3877c148d4c6a901a3d87ed680478931dc9b6f0871af0ab879b69ac").is_provably_unspendable(), false);
        assert_eq!(hex_script!("03800000").is_provably_unspendable(), false);
        // This one is cool -- a 2-of-4 multisig with four pks given, only two of which are legit
        assert_eq!(hex_script!("522103bb52138972c48a132fc1f637858c5189607dd0f7fe40c4f20f6ad65f2d389ba42103bb52138972c48a132fc1f637858c5189607dd0f7fe40c4f20f6ad65f2d389ba45f6054ae").is_provably_unspendable(), false);
        assert_eq!(hex_script!("64635167006867630067516868").is_provably_unspendable(), false);
        // This one is on mainnet oeO
        assert_eq!(hex_script!("827651a0698faaa9a8a7a687").is_provably_unspendable(), false);
        // gmaxwell found this one
        assert_eq!(hex_script!("76009f69905160a56b210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71ad6c").is_provably_unspendable(), false);
    }

    #[test]
    fn script_json_serialize() {
        use strason;

        let original = hex_script!("827651a0698faaa9a8a7a687");
        let json = strason::from_serialize(&original).unwrap();
        assert_eq!(json.to_bytes(), b"\"827651a0698faaa9a8a7a687\"");
        assert_eq!(json.string(), Some("827651a0698faaa9a8a7a687"));
        let des = json.into_deserialize().unwrap();
        assert_eq!(original, des);
    }

    #[test]
    fn script_debug_display() {
        assert_eq!(format!("{:?}", hex_script!("6363636363686868686800")),
                   "Script(OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0)");
        assert_eq!(format!("{}", hex_script!("6363636363686868686800")),
                   "Script(OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0)");
        assert_eq!(format!("{}", hex_script!("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac")),
                   "Script(OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG)");
    }
}


