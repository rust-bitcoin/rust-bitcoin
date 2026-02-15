// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network-related network messages.
//!
//! This module defines network messages which describe peers and their
//! capabilities.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::{encode, Decodable, Encodable, ReadExt, WriteExt};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, BytesEncoder, CompactSizeEncoder, Decoder4,
    Encoder2, Encoder4,
};
use hashes::sha256d;
use internals::write_err;
use io::{BufRead, Write};

use crate::address::Address;
use crate::consensus::{impl_consensus_encoding, impl_vec_wrapper};
use crate::{ProtocolVersion, ServiceFlags};

// Some simple messages

/// The `version` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct VersionMessage {
    /// The P2P network protocol version
    pub version: ProtocolVersion,
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
    pub user_agent: UserAgent,
    /// The height of the maximum-work blockchain that the peer is aware of
    pub start_height: i32,
    /// Whether the receiving peer should relay messages to the sender; used
    /// if the sender is bandwidth-limited and would like to support bloom
    /// filtering. Defaults to false.
    pub relay: bool,
}

impl VersionMessage {
    /// Constructs a new `version` message with `relay` set to false
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: ProtocolVersion,
        services: ServiceFlags,
        timestamp: i64,
        receiver: Address,
        sender: Address,
        nonce: u64,
        user_agent: UserAgent,
        start_height: i32,
    ) -> Self {
        Self {
            version,
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

/// A bitcoin user agent defined by BIP-0014. The user agent is sent in the version message when a
/// connection between two peers is established. It is intended to advertise client software in a
/// well-defined format.
///
/// ref: <https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgent {
    user_agent: String,
}

encoding::encoder_newtype! {
    /// The encoder for a [`UserAgent`] string.
    pub struct UserAgentEncoder<'e>(Encoder2<CompactSizeEncoder, BytesEncoder<'e>>);
}

impl encoding::Encodable for UserAgent {
    type Encoder<'e> = UserAgentEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        UserAgentEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.user_agent.len()),
            BytesEncoder::without_length_prefix(self.user_agent.as_bytes()),
        ))
    }
}

type UserAgentInnerDecoder = ByteVecDecoder;

/// The decoder for the [`UserAgent`] message.
pub struct UserAgentDecoder(UserAgentInnerDecoder);

impl encoding::Decoder for UserAgentDecoder {
    type Output = UserAgent;
    type Error = UserAgentDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(UserAgentDecoderError::Decoder)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(UserAgentDecoderError::Decoder)?;
        let user_agent =
            String::from_utf8(bytes).map_err(|_| UserAgentDecoderError::InvalidUtf8)?;
        Ok(UserAgent { user_agent })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for UserAgent {
    type Decoder = UserAgentDecoder;

    fn decoder() -> Self::Decoder { UserAgentDecoder(UserAgentInnerDecoder::new()) }
}

/// An error decoding a [`UserAgent`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAgentDecoderError {
    /// Inner decoder error.
    Decoder(<UserAgentInnerDecoder as encoding::Decoder>::Error),
    /// The string did not contain valid UTF-8.
    InvalidUtf8,
}

impl From<Infallible> for UserAgentDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for UserAgentDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(d) => write_err!(f, "useragent error"; d),
            Self::InvalidUtf8 => write!(f, "invalid utf-8."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UserAgentDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(d) => Some(d),
            Self::InvalidUtf8 => None,
        }
    }
}

impl_consensus_encoding!(UserAgent, user_agent);

impl UserAgent {
    const MAX_USER_AGENT_LEN: usize = 256;

    fn panic_invalid_chars(agent_str: &str) {
        assert!(
            !agent_str.chars().any(|c| matches!(c, '/' | '(' | ')' | ':')),
            "user agent configuration cannot contain: / ( ) :"
        );
    }

    fn panic_max_len(agent_str: &str) {
        assert!(
            agent_str.chars().count() <= Self::MAX_USER_AGENT_LEN,
            "user agent cannot exceed 256 characters."
        );
    }
    /// Builds a new user agent from the lowest level client software. For example: `Satoshi` is
    /// used by Bitcoin Core.
    ///
    /// # Panics
    ///
    /// If the client name contains one of: `/ ( ) :` or the user agent exceeds 256 characters.
    pub fn new<S: AsRef<str>>(client_name: S, client_version: &UserAgentVersion) -> Self {
        let parsed_name = client_name.as_ref();
        Self::panic_invalid_chars(parsed_name);
        let agent = format!("/{parsed_name}:{client_version}/");
        Self::panic_max_len(&agent);
        Self { user_agent: agent }
    }

    /// Builds a user agent, ignoring BIP-0014 recommendations.
    pub fn from_nonstandard<S: ToString>(agent: &S) -> Self {
        Self { user_agent: agent.to_string() }
    }

    /// Adds a client to the user agent string. Examples may include the name of a wallet software.
    ///
    /// # Panics
    ///
    /// If the client name contains one of: `/ ( ) :` or the user agent exceeds 256 characters.
    #[must_use]
    pub fn add_client<S: AsRef<str>>(
        mut self,
        client_name: S,
        client_version: &UserAgentVersion,
    ) -> Self {
        let parsed_name = client_name.as_ref();
        Self::panic_invalid_chars(parsed_name);
        let agent = format!("{parsed_name}:{client_version}/");
        self.user_agent.push_str(&agent);
        Self::panic_max_len(&self.user_agent);
        self
    }
}

impl std::fmt::Display for UserAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.user_agent.fmt(f) }
}

impl From<UserAgent> for String {
    fn from(agent: UserAgent) -> Self { agent.user_agent }
}

/// A software version field for inclusion in a user agent specified by BIP-0014.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentVersion {
    version: ClientSoftwareVersion,
    comments: Option<String>,
}

impl UserAgentVersion {
    /// Creates a user agent client version associated with a name.
    pub const fn new(software_version: ClientSoftwareVersion) -> Self {
        Self { version: software_version, comments: None }
    }

    /// Adds a comment to the version. Typical comments describe the operating system or platform
    /// that is executing the program, however these may be any comment.
    ///
    /// An example may include `Android`.
    ///
    /// # Panics
    ///
    /// If the client name contains one of: `/ ( ) :`
    #[must_use]
    pub fn push_comment<S: AsRef<str>>(mut self, comment: S) -> Self {
        let parsed_comment = comment.as_ref();
        UserAgent::panic_invalid_chars(parsed_comment);
        match self.comments {
            Some(mut comment) => {
                let semi_colon_delimiter = format!("; {parsed_comment}");
                comment.push_str(&semi_colon_delimiter);
                self.comments = Some(comment);
            }
            None => self.comments = Some(parsed_comment.to_string()),
        }
        self
    }
}

impl std::fmt::Display for UserAgentVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut software_version = self.version.to_string();
        if let Some(comments) = &self.comments {
            let comments = format!("({comments})");
            software_version.push_str(&comments);
        }
        software_version.fmt(f)
    }
}

/// Software tagged by version number or date for inclusion in a user agent field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientSoftwareVersion {
    /// Semantic versioning release.
    SemVer {
        /// X.0.0
        major: u16,
        /// 0.X.0
        minor: u16,
        /// 0.0.X
        revision: u16,
    },
    /// The release date of a software.
    Date {
        /// Year, represented as 4 digits
        yyyy: u16,
        /// The month
        mm: u8,
        /// The day
        dd: u8,
    },
}

impl std::fmt::Display for ClientSoftwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Date { yyyy, mm, dd } => format!("{yyyy}{mm:02}{dd:02}").fmt(f),
            Self::SemVer { major, minor, revision } => format!("{major}.{minor}.{revision}").fmt(f),
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

encoding::encoder_newtype! {
    /// The encoder type for a [`RejectReason`].
    pub struct RejectReasonEncoder<'e>(ArrayEncoder<1>);
}

impl encoding::Encodable for RejectReason {
    type Encoder<'e> = RejectReasonEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectReasonEncoder::new(ArrayEncoder::without_length_prefix([*self as u8]))
    }
}

/// The decoder type for a [`RejectReason`].
pub struct RejectReasonDecoder(ArrayDecoder<1>);

impl encoding::Decoder for RejectReasonDecoder {
    type Output = RejectReason;
    type Error = RejectReasonDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(RejectReasonDecoderError::Decoder)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let code_arr = self.0.end().map_err(RejectReasonDecoderError::Decoder)?;
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

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for RejectReason {
    type Decoder = RejectReasonDecoder;

    fn decoder() -> Self::Decoder { RejectReasonDecoder(ArrayDecoder::new()) }
}

/// Errors occuring when decoding a [`RejectReason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReasonDecoderError {
    /// Inner decoder error.
    Decoder(<ArrayDecoder<1> as encoding::Decoder>::Error),
    /// Unknown reject code.
    UnknownRejectCode(u8),
}

impl From<Infallible> for RejectReasonDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for RejectReasonDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(d) => write_err!(f, "rejectreason error"; d),
            Self::UnknownRejectCode(code) => write!(f, "unknown reject code {}", code),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RejectReasonDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(e) => Some(e),
            Self::UnknownRejectCode(_) => None,
        }
    }
}

impl Encodable for RejectReason {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[*self as u8])?;
        Ok(1)
    }
}

impl Decodable for RejectReason {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0x01 => Self::Malformed,
            0x10 => Self::Invalid,
            0x11 => Self::Obsolete,
            0x12 => Self::Duplicate,
            0x40 => Self::NonStandard,
            0x41 => Self::Dust,
            0x42 => Self::Fee,
            0x43 => Self::Checkpoint,
            _ => return Err(crate::consensus::parse_failed_error("unknown reject code")),
        })
    }
}

/// Reject message might be sent by peers rejecting one of our messages
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Reject {
    /// message type rejected
    pub message: Cow<'static, str>,
    /// reason of rejection as code
    pub ccode: RejectReason,
    /// reason of rejection
    pub reason: Cow<'static, str>,
    /// reference to rejected item
    pub hash: sha256d::Hash,
}

encoding::encoder_newtype! {
    /// The encoder type for a [`Reject`] message.
    pub struct RejectEncoder<'e>(
        Encoder4<
            Encoder2<CompactSizeEncoder, BytesEncoder<'e>>,
            RejectReasonEncoder<'e>,
            Encoder2<CompactSizeEncoder, BytesEncoder<'e>>,
            ArrayEncoder<32>,
        >
    );
}

impl encoding::Encodable for Reject {
    type Encoder<'e> = RejectEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectEncoder::new(Encoder4::new(
            Encoder2::new(
                CompactSizeEncoder::new(self.message.len()),
                BytesEncoder::without_length_prefix(self.message.as_bytes()),
            ),
            self.ccode.encoder(),
            Encoder2::new(
                CompactSizeEncoder::new(self.reason.len()),
                BytesEncoder::without_length_prefix(self.reason.as_bytes()),
            ),
            ArrayEncoder::without_length_prefix(self.hash.to_byte_array()),
        ))
    }
}

type RejectInnerDecoder =
    Decoder4<ByteVecDecoder, RejectReasonDecoder, ByteVecDecoder, ArrayDecoder<32>>;

/// The decoder type for a [`Reject`] message.
pub struct RejectDecoder(RejectInnerDecoder);

impl encoding::Decoder for RejectDecoder {
    type Output = Reject;
    type Error = RejectDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(RejectDecoderError::Decoder)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (message, ccode, reason, hash) = self.0.end().map_err(RejectDecoderError::Decoder)?;
        let message = String::from_utf8(message)
            .map_err(|_| RejectDecoderError::InvalidUtf8)
            .map(Cow::Owned)?;
        let reason = String::from_utf8(reason)
            .map_err(|_| RejectDecoderError::InvalidUtf8)
            .map(Cow::Owned)?;
        let hash = sha256d::Hash::from_byte_array(hash);
        Ok(Reject { message, ccode, reason, hash })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for Reject {
    type Decoder = RejectDecoder;

    fn decoder() -> Self::Decoder {
        RejectDecoder(Decoder4::new(
            ByteVecDecoder::new(),
            RejectReason::decoder(),
            ByteVecDecoder::new(),
            ArrayDecoder::new(),
        ))
    }
}

/// Errors occuring when decoding a [`Reject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectDecoderError {
    /// Inner decoder error.
    Decoder(<RejectInnerDecoder as encoding::Decoder>::Error),
    /// Invalid UTF-8 string.
    InvalidUtf8,
}

impl From<Infallible> for RejectDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for RejectDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(d) => write_err!(f, "reject error"; d),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RejectDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(d) => Some(d),
            Self::InvalidUtf8 => None,
        }
    }
}

impl_consensus_encoding!(Reject, message, ccode, reason, hash);

/// A deprecated message type that was used to notify users of system changes. Due to a number of
/// vulnerabilities, alerts are no longer used. A final alert was sent as of Bitcoin Core 0.14.0,
/// and is sent to any node that is advertising a potentially vulnerable protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert(Vec<u8>);

impl Alert {
    const FINAL_ALERT: [u8; 96] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 127, 0, 0, 0, 0, 255, 255, 255, 127,
        254, 255, 255, 127, 1, 255, 255, 255, 127, 0, 0, 0, 0, 255, 255, 255, 127, 0, 255, 255,
        255, 127, 0, 47, 85, 82, 71, 69, 78, 84, 58, 32, 65, 108, 101, 114, 116, 32, 107, 101, 121,
        32, 99, 111, 109, 112, 114, 111, 109, 105, 115, 101, 100, 44, 32, 117, 112, 103, 114, 97,
        100, 101, 32, 114, 101, 113, 117, 105, 114, 101, 100, 0,
    ];

    /// Builds the final alert to send to a potentially vulnerable peer.
    pub fn final_alert() -> Self { Self(Self::FINAL_ALERT.into()) }

    /// The final alert advertised by Bitcoin Core. This alert is sent if the advertised protocol
    /// version is vulnerable to the alert-system vulnerabilities.
    pub fn is_final_alert(&self) -> bool { self.0.eq(&Self::FINAL_ALERT) }
}

encoding::encoder_newtype! {
    /// The encoder type for an [`Alert`] message.
    pub struct AlertEncoder<'e>(Encoder2<CompactSizeEncoder, BytesEncoder<'e>>);
}

impl encoding::Encodable for Alert {
    type Encoder<'e> = AlertEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AlertEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            BytesEncoder::without_length_prefix(&self.0),
        ))
    }
}

type AlertInnerDecoder = ByteVecDecoder;

/// The decoder for the [`Alert`] message.
pub struct AlertDecoder(AlertInnerDecoder);

impl encoding::Decoder for AlertDecoder {
    type Output = Alert;
    type Error = AlertDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AlertDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(Alert(self.0.end().map_err(AlertDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for Alert {
    type Decoder = AlertDecoder;

    fn decoder() -> Self::Decoder { AlertDecoder(AlertInnerDecoder::new()) }
}

/// An error decoding a [`Alert`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertDecoderError(<AlertInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for AlertDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for AlertDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "alert error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlertDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_vec_wrapper!(Alert, Vec<u8>);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ClientSoftwareVersion {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match bool::arbitrary(u)? {
            true => Ok(Self::Date { yyyy: u.arbitrary()?, mm: u.arbitrary()?, dd: u.arbitrary()? }),
            false => Ok(Self::SemVer {
                major: u.arbitrary()?,
                minor: u.arbitrary()?,
                revision: u.arbitrary()?,
            }),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for UserAgentVersion {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for UserAgent {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary::<String>()?, &u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for VersionMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
        ))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for RejectReason {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=7)? {
            0 => Ok(Self::Malformed),
            1 => Ok(Self::Invalid),
            2 => Ok(Self::Obsolete),
            3 => Ok(Self::Duplicate),
            4 => Ok(Self::NonStandard),
            5 => Ok(Self::Dust),
            6 => Ok(Self::Fee),
            _ => Ok(Self::Checkpoint),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Reject {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            message: u.arbitrary::<String>()?.into(),
            ccode: u.arbitrary()?,
            reason: u.arbitrary::<String>()?.into(),
            hash: sha256d::Hash::from_byte_array(u.arbitrary()?),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Alert {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<u8>::arbitrary(u)?))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use bitcoin::consensus::encode::{deserialize, serialize};
    use hex_lit::hex;

    use super::*;

    #[test]
    fn version_message_test() {
        // This message is from my satoshi node, morning of May 27 2014
        let from_sat = hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001");

        let decode: Result<VersionMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.services, ServiceFlags::NETWORK);
        assert_eq!(real_decode.timestamp, 1_401_217_254);
        // address decodes should be covered by Address tests
        assert_eq!(real_decode.nonce, 16_735_069_437_859_780_935);
        assert_eq!(
            real_decode.user_agent,
            UserAgent::new(
                "Satoshi",
                &UserAgentVersion::new(ClientSoftwareVersion::SemVer {
                    major: 0,
                    minor: 9,
                    revision: 99
                })
            )
        );
        assert_eq!(real_decode.start_height, 302_892);
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

    #[test]
    fn alert_message_test() {
        let alert_hex = hex!("60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c207570677261646520726571756972656400");
        let alert: Alert = deserialize(&alert_hex).unwrap();
        assert!(alert.is_final_alert());
    }

    #[test]
    fn test_user_agent() {
        let client_name = "Satoshi";
        let client_version = UserAgentVersion::new(ClientSoftwareVersion::SemVer {
            major: 5,
            minor: 12,
            revision: 0,
        });
        let user_agent = UserAgent::new(client_name, &client_version);
        assert_eq!("/Satoshi:5.12.0/", user_agent.to_string());
        let wallet_name = "bitcoin-qt";
        let wallet_version = UserAgentVersion::new(ClientSoftwareVersion::SemVer {
            major: 0,
            minor: 8,
            revision: 0,
        });
        let user_agent = user_agent.add_client(wallet_name, &wallet_version);
        assert_eq!("/Satoshi:5.12.0/bitcoin-qt:0.8.0/", user_agent.to_string());
        let client_name = "BitcoinJ";
        let client_version =
            UserAgentVersion::new(ClientSoftwareVersion::Date { yyyy: 2011, mm: 1, dd: 28 });
        let user_agent = UserAgent::new(client_name, &client_version);
        assert_eq!("/BitcoinJ:20110128/", user_agent.to_string());
        let wallet_name = "Electrum";
        let wallet_version = UserAgentVersion::new(ClientSoftwareVersion::SemVer {
            major: 0,
            minor: 9,
            revision: 0,
        });
        let wallet_version = wallet_version.push_comment("Ubuntu");
        let wallet_version = wallet_version.push_comment("24");
        let user_agent = user_agent.add_client(wallet_name, &wallet_version);
        assert_eq!("/BitcoinJ:20110128/Electrum:0.9.0(Ubuntu; 24)/", user_agent.to_string());
    }

    #[test]
    #[should_panic(expected = "user agent configuration cannot contain: / ( ) :")]
    fn test_incorrect_user_agent() {
        let client_name = "Satoshi/";
        let client_version = UserAgentVersion::new(ClientSoftwareVersion::SemVer {
            major: 5,
            minor: 12,
            revision: 0,
        });
        UserAgent::new(client_name, &client_version);
    }
}
