// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network-related network messages.
//!
//! This module defines network messages which describe peers and their
//! capabilities.
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;
#[cfg(feature = "encoding")]
use core::fmt;

use hashes::sha256d;
#[cfg(feature = "encoding")]
use hashes::Hash as _;
use io::{Read, Write};

use crate::consensus::{encode, Decodable, Encodable, ReadExt};
use crate::internal_macros::impl_consensus_encoding;
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;
use crate::p2p;
use crate::p2p::address::Address;
#[cfg(feature = "encoding")]
use crate::p2p::address::AddressDecoder;
use crate::p2p::ServiceFlags;
use crate::prelude::*;

// Some simple messages

/// The `version` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct VersionMessage {
    /// The P2P network protocol version
    pub version: u32,
    /// A bitmask describing the services supported by this node
    pub services: ServiceFlags,
    /// The time at which the `version` message was sent
    pub timestamp: i64,
    /// The network address of the peer receiving the message
    pub receiver: Address,
    /// The network address of the peer sending the message
    pub sender: Address,
    /// A random nonce used to detect loops in the network
    ///
    /// The nonce can be used to detect situations when a node accidentally
    /// connects to itself. Set it to a random value and, in case of incoming
    /// connections, compare the value - same values mean self-connection.
    ///
    /// If your application uses P2P to only fetch the data and doesn't listen
    /// you may just set it to 0.
    pub nonce: u64,
    /// A string describing the peer's software
    pub user_agent: String,
    /// The height of the maximum-work blockchain that the peer is aware of
    pub start_height: i32,
    /// Whether the receiving peer should relay messages to the sender; used
    /// if the sender is bandwidth-limited and would like to support bloom
    /// filtering. Defaults to false.
    pub relay: bool,
}

impl VersionMessage {
    /// Constructs a new `version` message with `relay` set to false
    pub fn new(
        services: ServiceFlags,
        timestamp: i64,
        receiver: Address,
        sender: Address,
        nonce: u64,
        user_agent: String,
        start_height: i32,
    ) -> VersionMessage {
        VersionMessage {
            version: p2p::PROTOCOL_VERSION,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            user_agent,
            start_height,
            relay: false,
        }
    }
}

impl_consensus_encoding!(
    VersionMessage,
    version,
    services,
    timestamp,
    receiver,
    sender,
    nonce,
    user_agent,
    start_height,
    relay
);

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`VersionMessage`] type.
    #[derive(Debug, Clone)]
    pub struct VersionMessageEncoder<'e>(
        encoding::Encoder2<
            encoding::Encoder3<
                encoding::ArrayEncoder<4>,
                crate::p2p::ServiceFlagsEncoder<'e>,
                encoding::ArrayEncoder<8>
            >,
            encoding::Encoder6<
                crate::p2p::address::AddressEncoder<'e>,
                crate::p2p::address::AddressEncoder<'e>,
                encoding::ArrayEncoder<8>,
                encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>,
                encoding::ArrayEncoder<4>,
                encoding::ArrayEncoder<1>
            >
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for VersionMessage {
    type Encoder<'e> = VersionMessageEncoder<'e>;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionMessageEncoder::new(encoding::Encoder2::new(
            encoding::Encoder3::new(
                encoding::ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
                self.services.encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.timestamp.to_le_bytes()),
            ),
            encoding::Encoder6::new(
                self.receiver.encoder(),
                self.sender.encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()),
                encoding::Encoder2::new(
                    encoding::CompactSizeEncoder::new(self.user_agent.len()),
                    encoding::BytesEncoder::without_length_prefix(self.user_agent.as_bytes()),
                ),
                encoding::ArrayEncoder::without_length_prefix(self.start_height.to_le_bytes()),
                encoding::ArrayEncoder::without_length_prefix([u8::from(self.relay)]),
            ),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for VersionMessage {
    type Decoder = VersionMessageDecoder;
}

#[cfg(feature = "encoding")]
type VersionMessageInnerDecoder = encoding::Decoder2<
    encoding::Decoder3<
        encoding::ArrayDecoder<4>,
        crate::p2p::ServiceFlagsDecoder,
        encoding::ArrayDecoder<8>,
    >,
    encoding::Decoder6<
        AddressDecoder,
        AddressDecoder,
        encoding::ArrayDecoder<8>,
        encoding::ByteVecDecoder,
        encoding::ArrayDecoder<4>,
        encoding::ArrayDecoder<1>,
    >,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The Decoder for [`VersionMessage`].
    #[derive(Debug, Default, Clone)]
    pub struct VersionMessageDecoder(VersionMessageInnerDecoder);

    fn map_push_bytes_err(
        err: <VersionMessageInnerDecoder as encoding::Decoder>::Error
    ) -> VersionMessageDecoderError {
        VersionMessageDecoderError::Decoder(err)
    }

    fn end(
        result: Result<<VersionMessageInnerDecoder as encoding::Decoder>::Output, <VersionMessageInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<VersionMessage, VersionMessageDecoderError> {
        let (
            (version, services, timestamp),
            (receiver, sender, nonce, user_agent, start_height, relay),
        ) = result.map_err(VersionMessageDecoderError::Decoder)?;
        let user_agent = String::from_utf8(user_agent).map_err(|_| VersionMessageDecoderError::InvalidUtf8)?;

        Ok(VersionMessage {
            version: u32::from_le_bytes(version),
            services,
            timestamp: i64::from_le_bytes(timestamp),
            receiver,
            sender,
            nonce: u64::from_le_bytes(nonce),
            user_agent,
            start_height: i32::from_le_bytes(start_height),
            relay: relay[0] != 0,
        })
    }
}

/// Errors occurring when decoding a [`VersionMessage`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionMessageDecoderError {
    /// Inner decoder error.
    Decoder(<VersionMessageInnerDecoder as encoding::Decoder>::Error),
    /// Invalid UTF-8 in the user agent.
    InvalidUtf8,
}

#[cfg(feature = "encoding")]
impl From<Infallible> for VersionMessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for VersionMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(e) => write_err!(f, "version message decoder error"; e),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for VersionMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(e) => Some(e),
            Self::InvalidUtf8 => None,
        }
    }
}

/// message rejection reason as a code
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum RejectReason {
    /// malformed message
    Malformed = 0x01,
    /// invalid message
    Invalid = 0x10,
    /// obsolete message
    Obsolete = 0x11,
    /// duplicate message
    Duplicate = 0x12,
    /// nonstandard transaction
    NonStandard = 0x40,
    /// an output is below dust limit
    Dust = 0x41,
    /// insufficient fee
    Fee = 0x42,
    /// checkpoint
    Checkpoint = 0x43,
}

impl Encodable for RejectReason {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[*self as u8])?;
        Ok(1)
    }
}

impl Decodable for RejectReason {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0x01 => RejectReason::Malformed,
            0x10 => RejectReason::Invalid,
            0x11 => RejectReason::Obsolete,
            0x12 => RejectReason::Duplicate,
            0x40 => RejectReason::NonStandard,
            0x41 => RejectReason::Dust,
            0x42 => RejectReason::Fee,
            0x43 => RejectReason::Checkpoint,
            _ => return Err(encode::Error::ParseFailed("unknown reject code")),
        })
    }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// Encoder type for a [`RejectReason`].
    #[derive(Debug, Clone)]
    pub struct RejectReasonEncoder<'e>(encoding::ArrayEncoder<1>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for RejectReason {
    type Encoder<'e> = RejectReasonEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectReasonEncoder::new(encoding::ArrayEncoder::without_length_prefix([*self as u8]))
    }
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`RejectReason`].
    #[derive(Debug, Default, Clone)]
    pub struct RejectReasonDecoder(encoding::ArrayDecoder<1>);

    fn map_push_bytes_err(err: encoding::UnexpectedEofError) -> RejectReasonDecoderError {
        RejectReasonDecoderError::Decoder(err)
    }

    fn end(
        result: Result<[u8; 1], encoding::UnexpectedEofError>
    ) -> Result<RejectReason, RejectReasonDecoderError> {
        let code_arr = result.map_err(RejectReasonDecoderError::Decoder)?;
        let code = u8::from_le_bytes(code_arr);
        Ok(match code {
            0x01 => RejectReason::Malformed,
            0x10 => RejectReason::Invalid,
            0x11 => RejectReason::Obsolete,
            0x12 => RejectReason::Duplicate,
            0x40 => RejectReason::NonStandard,
            0x41 => RejectReason::Dust,
            0x42 => RejectReason::Fee,
            0x43 => RejectReason::Checkpoint,
            unknown => return Err(RejectReasonDecoderError::UnknownRejectCode(unknown)),
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for RejectReason {
    type Decoder = RejectReasonDecoder;

    fn decoder() -> Self::Decoder { RejectReasonDecoder(encoding::ArrayDecoder::new()) }
}

/// Errors occurring when decoding a [`RejectReason`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReasonDecoderError {
    /// Inner decoder error.
    Decoder(<encoding::ArrayDecoder<1> as encoding::Decoder>::Error),
    /// Unknown reject code.
    UnknownRejectCode(u8),
}

#[cfg(feature = "encoding")]
impl From<Infallible> for RejectReasonDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for RejectReasonDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(e) => write_err!(f, "rejectreason error"; e),
            Self::UnknownRejectCode(code) => write!(f, "unknown reject code {}", code),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for RejectReasonDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(e) => Some(e),
            Self::UnknownRejectCode(_) => None,
        }
    }
}

/// Reject message might be sent by peers rejecting one of our messages
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Reject {
    /// message type rejected
    pub message: Cow<'static, str>,
    /// reason of rejection as code
    pub ccode: RejectReason,
    /// reason of rejectection
    pub reason: Cow<'static, str>,
    /// reference to rejected item
    pub hash: sha256d::Hash,
}

impl_consensus_encoding!(Reject, message, ccode, reason, hash);

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// Encoder type for a [`Reject`] message.
    #[derive(Debug, Clone)]
    pub struct RejectEncoder<'e>(
        encoding::Encoder4<
            encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>,
            RejectReasonEncoder<'e>,
            encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>,
            encoding::ArrayEncoder<32>
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Reject {
    type Encoder<'e> = RejectEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectEncoder::new(encoding::Encoder4::new(
            encoding::Encoder2::new(
                encoding::CompactSizeEncoder::new(self.message.len()),
                encoding::BytesEncoder::without_length_prefix(self.message.as_bytes()),
            ),
            self.ccode.encoder(),
            encoding::Encoder2::new(
                encoding::CompactSizeEncoder::new(self.reason.len()),
                encoding::BytesEncoder::without_length_prefix(self.reason.as_bytes()),
            ),
            encoding::ArrayEncoder::without_length_prefix(self.hash.to_byte_array()),
        ))
    }
}

#[cfg(feature = "encoding")]
type RejectInnerDecoder = encoding::Decoder4<
    encoding::ByteVecDecoder,
    RejectReasonDecoder,
    encoding::ByteVecDecoder,
    encoding::ArrayDecoder<32>,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`Reject`] message.
    #[derive(Debug, Default, Clone)]
    pub struct RejectDecoder(RejectInnerDecoder);

    fn map_push_bytes_err(
        err: <RejectInnerDecoder as encoding::Decoder>::Error
    ) -> RejectDecoderError {
        RejectDecoderError::Decoder(err)
    }

    fn end(
        result: Result<<RejectInnerDecoder as encoding::Decoder>::Output, <RejectInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Reject, RejectDecoderError> {
        let (message, ccode, reason, hash) = result.map_err(RejectDecoderError::Decoder)?;
        let message = String::from_utf8(message).map_err(|_| RejectDecoderError::InvalidUtf8)?;
        let reason = String::from_utf8(reason).map_err(|_| RejectDecoderError::InvalidUtf8)?;

        Ok(Reject {
            message: Cow::Owned(message),
            ccode,
            reason: Cow::Owned(reason),
            hash: sha256d::Hash::from_byte_array(hash),
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Reject {
    type Decoder = RejectDecoder;

    fn decoder() -> Self::Decoder {
        RejectDecoder(encoding::Decoder4::new(
            encoding::ByteVecDecoder::new(),
            RejectReason::decoder(),
            encoding::ByteVecDecoder::new(),
            encoding::ArrayDecoder::new(),
        ))
    }
}

/// Errors occurring when decoding a [`Reject`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectDecoderError {
    /// Inner decoder error.
    Decoder(<RejectInnerDecoder as encoding::Decoder>::Error),
    /// Invalid UTF-8.
    InvalidUtf8,
}

#[cfg(feature = "encoding")]
impl From<Infallible> for RejectDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for RejectDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(e) => write_err!(f, "reject error"; e),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for RejectDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(e) => Some(e),
            Self::InvalidUtf8 => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hashes::sha256d;
    use hex::test_hex_unwrap as hex;

    use super::{Reject, RejectReason, VersionMessage};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::p2p::ServiceFlags;

    #[test]
    fn version_message_test() {
        // This message is from my satoshi node, morning of May 27 2014
        let from_sat = hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001");

        let decode: Result<VersionMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.services, ServiceFlags::NETWORK);
        assert_eq!(real_decode.timestamp, 1401217254);
        // address decodes should be covered by Address tests
        assert_eq!(real_decode.nonce, 16735069437859780935);
        assert_eq!(real_decode.user_agent, "/Satoshi:0.9.99/".to_string());
        assert_eq!(real_decode.start_height, 302892);
        assert!(real_decode.relay);

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn reject_message_test() {
        let reject_tx_conflict = hex!("027478121474786e2d6d656d706f6f6c2d636f6e666c69637405df54d3860b3c41806a3546ab48279300affacf4b88591b229141dcf2f47004");
        let reject_tx_nonfinal = hex!("02747840096e6f6e2d66696e616c259bbe6c83db8bbdfca7ca303b19413dc245d9f2371b344ede5f8b1339a5460b");

        let decode_result_conflict: Result<Reject, _> = deserialize(&reject_tx_conflict);
        let decode_result_nonfinal: Result<Reject, _> = deserialize(&reject_tx_nonfinal);

        assert!(decode_result_conflict.is_ok());
        assert!(decode_result_nonfinal.is_ok());

        let conflict = decode_result_conflict.unwrap();
        assert_eq!("tx", conflict.message);
        assert_eq!(RejectReason::Duplicate, conflict.ccode);
        assert_eq!("txn-mempool-conflict", conflict.reason);
        assert_eq!(
            "0470f4f2dc4191221b59884bcffaaf00932748ab46356a80413c0b86d354df05"
                .parse::<sha256d::Hash>()
                .unwrap(),
            conflict.hash
        );

        let nonfinal = decode_result_nonfinal.unwrap();
        assert_eq!("tx", nonfinal.message);
        assert_eq!(RejectReason::NonStandard, nonfinal.ccode);
        assert_eq!("non-final", nonfinal.reason);
        assert_eq!(
            "0b46a539138b5fde4e341b37f2d945c23d41193b30caa7fcbd8bdb836cbe9b25"
                .parse::<sha256d::Hash>()
                .unwrap(),
            nonfinal.hash
        );

        assert_eq!(serialize(&conflict), reject_tx_conflict);
        assert_eq!(serialize(&nonfinal), reject_tx_nonfinal);
    }
}
