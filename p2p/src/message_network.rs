// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network-related network messages.
//!
//! This module defines network messages which describe peers and their
//! capabilities.

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, Decode as _, Decoder as _, Decoder2, Decoder4,
    Encoder4, PrefixedBytesEncoder,
};
use hashes::sha256d;

use self::error::VersionMessageDecoderErrorInner as Inner;
use crate::address::{Address, AddressDecoder};
use crate::{ProtocolVersion, ServiceFlags};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    AlertDecoderError, RejectDecoderError, RejectReasonDecoderError, UserAgentDecoderError,
    VersionMessageDecoderError,
};

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

encoding::encoder_newtype_exact! {
    /// The encoder for the [`VersionMessage`] type.
    #[derive(Debug, Clone)]
    pub struct VersionMessageEncoder<'e>(
        encoding::Encoder2<
            encoding::Encoder3<
                crate::ProtocolVersionEncoder<'e>,
                crate::ServiceFlagsEncoder<'e>,
                encoding::ArrayEncoder<8>
            >,
            encoding::Encoder6<
                crate::address::AddressEncoder<'e>,
                crate::address::AddressEncoder<'e>,
                encoding::ArrayEncoder<8>,
                UserAgentEncoder<'e>,
                encoding::ArrayEncoder<4>,
                encoding::ArrayEncoder<1>
            >
        >
    );
}

impl encoding::Encode for VersionMessage {
    type Encoder<'e>
        = VersionMessageEncoder<'e>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        VersionMessageEncoder::new(encoding::Encoder2::new(
            encoding::Encoder3::new(
                self.version.encoder(),
                self.services.encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.timestamp.to_le_bytes()),
            ),
            encoding::Encoder6::new(
                self.receiver.encoder(),
                self.sender.encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()),
                self.user_agent.encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.start_height.to_le_bytes()),
                encoding::ArrayEncoder::without_length_prefix([u8::from(self.relay)]),
            ),
        ))
    }
}

impl encoding::Decode for VersionMessage {
    type Decoder = VersionMessageDecoder;
}

/// Decoder for the mandatory prefix of a `version` payload: protocol version, services,
/// timestamp and the receiver address.
type VersionRequiredDecoder = Decoder4<
    crate::ProtocolVersionDecoder,
    crate::ServiceFlagsDecoder,
    ArrayDecoder<8>,
    AddressDecoder,
>;

/// Decoder for the sender address and the nonce.
///
/// Bitcoin Core reads these two as a single unit (`vRecv.ignore(26); vRecv >> nNonce;`) so a
/// payload is not allowed to stop between them.
type VersionSenderNonceDecoder = Decoder2<AddressDecoder, ArrayDecoder<8>>;

/// Byte length of the sender address plus the nonce.
const VERSION_SENDER_NONCE_LEN: usize = 34;

/// Position of the decoder inside a `version` payload.
///
/// The `After*` variants are stop points: a payload that ends there is accepted and the fields
/// which were not reached keep their Bitcoin Core defaults. Being inside one of the sub-decoder
/// variants means the payload ended in the middle of a field, which is rejected.
#[derive(Debug, Clone)]
enum VersionMessageDecoderState {
    Required(VersionRequiredDecoder),
    AfterRequired,
    SenderNonce(VersionSenderNonceDecoder),
    AfterSenderNonce,
    UserAgent(UserAgentDecoder),
    AfterUserAgent,
    StartHeight(ArrayDecoder<4>),
    AfterStartHeight,
    Relay(ArrayDecoder<1>),
    Done,
}

/// The Decoder for [`VersionMessage`].
///
/// Constructed with [`Default::default`] the decoder requires every field to be present, which is
/// the only thing it can do when nothing tells it where the payload ends.
///
/// Constructed with [`VersionMessageDecoder::with_payload_len`] the decoder is given the payload
/// length declared by the enclosing V1 message header. With that context it accepts the shorter
/// payloads Bitcoin Core accepts: everything after the receiver address is optional and missing
/// fields get Core's defaults (`sender` unroutable, `nonce` 1, `user_agent` empty, `start_height`
/// -1, `relay` true). See `net_processing.cpp` `PeerManagerImpl::ProcessMessage`.
///
/// Knowing the declared length is what makes [`encoding::Decoder::read_limit`] safe here. It
/// returns the number of payload bytes still unread rather than the number of bytes the next
/// field wants, so it never reaches zero while optional bytes are still in flight, and the caller
/// can never be told to stop early and hand this message's bytes to the next decoder.
#[derive(Debug, Clone)]
pub struct VersionMessageDecoder {
    state: VersionMessageDecoderState,
    /// Payload length declared by the enclosing message header, when there is one.
    payload_len: Option<usize>,
    /// Payload bytes consumed so far.
    consumed: usize,
    version: Option<ProtocolVersion>,
    services: Option<ServiceFlags>,
    timestamp: i64,
    receiver: Option<Address>,
    // Optional fields, pre-filled with the Bitcoin Core defaults.
    sender: Address,
    nonce: u64,
    user_agent: UserAgent,
    start_height: i32,
    relay: bool,
}

impl VersionMessageDecoder {
    fn new(payload_len: Option<usize>) -> Self {
        Self {
            state: VersionMessageDecoderState::Required(VersionRequiredDecoder::default()),
            payload_len,
            consumed: 0,
            version: None,
            services: None,
            timestamp: 0,
            receiver: None,
            sender: Address::useless(),
            nonce: 1,
            user_agent: UserAgent { user_agent: String::new() },
            start_height: -1,
            relay: true,
        }
    }

    /// Constructs a decoder for a `version` payload of `payload_len` bytes.
    ///
    /// The length comes from the enclosing message header. Supplying it is what allows the
    /// optional fields to be left out, the way Bitcoin Core allows it.
    pub fn with_payload_len(payload_len: usize) -> Self { Self::new(Some(payload_len)) }

    /// Returns true when the declared payload has been fully consumed, so an optional field
    /// boundary reached now is the end of the message.
    fn at_declared_end(&self) -> bool { self.payload_len == Some(self.consumed) }

    /// Drives the state machine over `bytes`, which the caller has already trimmed to the
    /// declared payload.
    fn push_within_payload(
        &mut self,
        bytes: &mut &[u8],
    ) -> Result<encoding::DecoderStatus, VersionMessageDecoderError> {
        use VersionMessageDecoderState as S;

        /// Feeds bytes to the sub-decoder held in the current state. On completion the state
        /// moves to the next stop point and the decoded value is handed back.
        macro_rules! advance {
            ($variant:ident, $decoder:expr, $wrap:path, $next:expr) => {{
                let before = bytes.len();
                let status =
                    $decoder.push_bytes(bytes).map_err(|e| VersionMessageDecoderError($wrap(e)))?;
                self.consumed += before - bytes.len();
                if status.needs_more() {
                    return Ok(encoding::DecoderStatus::NeedsMore);
                }
                let S::$variant(decoder) = mem::replace(&mut self.state, $next) else {
                    unreachable!("state was just matched")
                };
                decoder.end().map_err(|e| VersionMessageDecoderError($wrap(e)))?
            }};
        }

        /// Moves past a stop point, unless the declared payload says the message ends here.
        macro_rules! stop_or_continue {
            ($next:expr) => {{
                if self.at_declared_end() {
                    return Ok(encoding::DecoderStatus::Ready);
                }
                self.state = $next;
            }};
        }

        loop {
            match &mut self.state {
                S::Required(decoder) => {
                    let (version, services, timestamp, receiver) =
                        advance!(Required, decoder, Inner::Required, S::AfterRequired);
                    self.version = Some(version);
                    self.services = Some(services);
                    self.timestamp = i64::from_le_bytes(timestamp);
                    self.receiver = Some(receiver);
                }
                S::AfterRequired =>
                    stop_or_continue!(S::SenderNonce(VersionSenderNonceDecoder::default())),
                S::SenderNonce(decoder) => {
                    let (sender, nonce) =
                        advance!(SenderNonce, decoder, Inner::SenderNonce, S::AfterSenderNonce);
                    self.sender = sender;
                    self.nonce = u64::from_le_bytes(nonce);
                }
                S::AfterSenderNonce => stop_or_continue!(S::UserAgent(UserAgent::decoder())),
                S::UserAgent(decoder) => {
                    self.user_agent =
                        advance!(UserAgent, decoder, Inner::UserAgent, S::AfterUserAgent);
                }
                S::AfterUserAgent => stop_or_continue!(S::StartHeight(ArrayDecoder::<4>::new())),
                S::StartHeight(decoder) => {
                    let start_height =
                        advance!(StartHeight, decoder, Inner::StartHeight, S::AfterStartHeight);
                    self.start_height = i32::from_le_bytes(start_height);
                }
                S::AfterStartHeight => stop_or_continue!(S::Relay(ArrayDecoder::<1>::new())),
                S::Relay(decoder) => {
                    let relay = advance!(Relay, decoder, Inner::Relay, S::Done);
                    self.relay = relay[0] != 0;
                }
                S::Done => return Ok(encoding::DecoderStatus::Ready),
            }
        }
    }

    /// Assembles the message. Only called from a stop point, so every field is either decoded or
    /// still holding its Bitcoin Core default.
    fn build(self) -> Result<VersionMessage, VersionMessageDecoderError> {
        let (Some(version), Some(services), Some(receiver)) =
            (self.version, self.services, self.receiver)
        else {
            return Err(VersionMessageDecoderError(Inner::UnexpectedEnd));
        };
        Ok(VersionMessage {
            version,
            services,
            timestamp: self.timestamp,
            receiver,
            sender: self.sender,
            nonce: self.nonce,
            user_agent: self.user_agent,
            start_height: self.start_height,
            relay: self.relay,
        })
    }
}

impl Default for VersionMessageDecoder {
    fn default() -> Self { Self::new(None) }
}

impl encoding::Decoder for VersionMessageDecoder {
    type Output = VersionMessage;
    type Error = VersionMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        let Some(payload_len) = self.payload_len else {
            return self.push_within_payload(bytes);
        };
        // Never read past the declared payload, the bytes after it belong to the next message.
        let allowed = payload_len.saturating_sub(self.consumed).min(bytes.len());
        let mut window = &bytes[..allowed];
        let status = self.push_within_payload(&mut window)?;
        let used = allowed - window.len();
        *bytes = &bytes[used..];
        Ok(status)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use VersionMessageDecoderState as S;

        if let Some(payload_len) = self.payload_len {
            if self.consumed != payload_len {
                return Err(VersionMessageDecoderError(Inner::PayloadLength {
                    expected: payload_len,
                    actual: self.consumed,
                }));
            }
        }
        // Stopping short is only legal when the declared payload length says the message really
        // ended here. Without that context every field is required.
        let truncation_allowed = self.payload_len.is_some();
        match &self.state {
            S::Done => self.build(),
            S::AfterRequired | S::AfterSenderNonce | S::AfterUserAgent | S::AfterStartHeight
                if truncation_allowed =>
                self.build(),
            _ => Err(VersionMessageDecoderError(Inner::UnexpectedEnd)),
        }
    }

    fn read_limit(&self) -> usize {
        use VersionMessageDecoderState as S;

        if matches!(self.state, S::Done) {
            return 0;
        }
        match self.payload_len {
            // The declared payload is the only honest limit: an optional field boundary is not
            // the end of the message unless the header says the payload ends there.
            Some(payload_len) => payload_len.saturating_sub(self.consumed),
            None => match &self.state {
                S::Required(decoder) => decoder.read_limit(),
                S::AfterRequired => VERSION_SENDER_NONCE_LEN,
                S::SenderNonce(decoder) => decoder.read_limit(),
                // At least the user agent length prefix.
                S::AfterSenderNonce => 1,
                S::UserAgent(decoder) => decoder.read_limit(),
                S::AfterUserAgent => 4,
                S::StartHeight(decoder) => decoder.read_limit(),
                S::AfterStartHeight => 1,
                S::Relay(decoder) => decoder.read_limit(),
                S::Done => 0,
            },
        }
    }
}

/// A Bitcoin user agent defined by BIP-0014. The user agent is sent in the version message when a
/// connection between two peers is established. It is intended to advertise client software in a
/// well-defined format.
///
/// ref: <https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgent {
    user_agent: String,
}

encoding::encoder_newtype_exact! {
    /// The encoder for a [`UserAgent`] string.
    #[derive(Debug, Clone)]
    pub struct UserAgentEncoder<'e>(PrefixedBytesEncoder<'e>);
}

impl encoding::Encode for UserAgent {
    type Encoder<'e> = UserAgentEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        UserAgentEncoder::new(PrefixedBytesEncoder::new(self.user_agent.as_bytes()))
    }
}

type UserAgentInnerDecoder = ByteVecDecoder;

crate::decoder_newtype! {
    /// The decoder for the [`UserAgent`] message.
    #[derive(Debug, Default, Clone)]
    pub struct UserAgentDecoder(UserAgentInnerDecoder);

    fn map_push_bytes_err(err: encoding::ByteVecDecoderError) -> UserAgentDecoderError {
        UserAgentDecoderError::Decoder(err)
    }

    fn end(
        result: Result<Vec<u8>, encoding::ByteVecDecoderError>
    ) -> Result<UserAgent, UserAgentDecoderError> {
        let bytes = result.map_err(UserAgentDecoderError::Decoder)?;
        let user_agent =
            String::from_utf8(bytes).map_err(|_| UserAgentDecoderError::InvalidUtf8)?;
        Ok(UserAgent { user_agent })
    }
}

impl encoding::Decode for UserAgent {
    type Decoder = UserAgentDecoder;

    fn decoder() -> Self::Decoder { UserAgentDecoder(UserAgentInnerDecoder::new()) }
}

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
    /// Constructs a user agent client version associated with a name.
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

encoding::encoder_newtype_exact! {
    /// The encoder type for a [`RejectReason`].
    #[derive(Debug, Clone)]
    pub struct RejectReasonEncoder<'e>(ArrayEncoder<1>);
}

impl encoding::Encode for RejectReason {
    type Encoder<'e> = RejectReasonEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectReasonEncoder::new(ArrayEncoder::without_length_prefix([*self as u8]))
    }
}

crate::decoder_newtype! {
    /// The decoder type for a [`RejectReason`].
    #[derive(Debug, Default, Clone)]
    pub struct RejectReasonDecoder(ArrayDecoder<1>);

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

impl encoding::Decode for RejectReason {
    type Decoder = RejectReasonDecoder;

    fn decoder() -> Self::Decoder { RejectReasonDecoder(ArrayDecoder::new()) }
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

encoding::encoder_newtype_exact! {
    /// The encoder type for a [`Reject`] message.
    #[derive(Debug, Clone)]
    pub struct RejectEncoder<'e>(
        Encoder4<
            PrefixedBytesEncoder<'e>,
            RejectReasonEncoder<'e>,
            PrefixedBytesEncoder<'e>,
            ArrayEncoder<32>,
        >
    );
}

impl encoding::Encode for Reject {
    type Encoder<'e> = RejectEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        RejectEncoder::new(Encoder4::new(
            PrefixedBytesEncoder::new(self.message.as_bytes()),
            self.ccode.encoder(),
            PrefixedBytesEncoder::new(self.reason.as_bytes()),
            ArrayEncoder::without_length_prefix(self.hash.to_byte_array()),
        ))
    }
}

type RejectInnerDecoder =
    Decoder4<ByteVecDecoder, RejectReasonDecoder, ByteVecDecoder, ArrayDecoder<32>>;

crate::decoder_newtype! {
    /// The decoder type for a [`Reject`] message.
    #[derive(Debug, Default, Clone)]
    pub struct RejectDecoder(RejectInnerDecoder);

    fn map_push_bytes_err(err: <RejectInnerDecoder as encoding::Decoder>::Error) -> RejectDecoderError {
        RejectDecoderError::Decoder(err)
    }

    fn end(
        result: Result<
            <RejectInnerDecoder as encoding::Decoder>::Output,
            <RejectInnerDecoder as encoding::Decoder>::Error,
        >
    ) -> Result<Reject, RejectDecoderError> {
        let (message, ccode, reason, hash) = result.map_err(RejectDecoderError::Decoder)?;
        let message = String::from_utf8(message)
            .map_err(|_| RejectDecoderError::InvalidUtf8)
            .map(Cow::Owned)?;
        let reason = String::from_utf8(reason)
            .map_err(|_| RejectDecoderError::InvalidUtf8)
            .map(Cow::Owned)?;
        let hash = sha256d::Hash::from_byte_array(hash);
        Ok(Reject { message, ccode, reason, hash })
    }
}

impl encoding::Decode for Reject {
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

encoding::encoder_newtype_exact! {
    /// The encoder type for an [`Alert`] message.
    #[derive(Debug, Clone)]
    pub struct AlertEncoder<'e>(PrefixedBytesEncoder<'e>);
}

impl encoding::Encode for Alert {
    type Encoder<'e> = AlertEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> { AlertEncoder::new(PrefixedBytesEncoder::new(&self.0)) }
}

type AlertInnerDecoder = ByteVecDecoder;

crate::decoder_newtype! {
    /// The decoder for the [`Alert`] message.
    #[derive(Debug, Default, Clone)]
    pub struct AlertDecoder(AlertInnerDecoder);

    fn end(
        result: Result<Vec<u8>, encoding::ByteVecDecoderError>
    ) -> Result<Alert, AlertDecoderError> {
        Ok(Alert(result.map_err(AlertDecoderError)?))
    }
}

impl encoding::Decode for Alert {
    type Decoder = AlertDecoder;

    fn decoder() -> Self::Decoder { AlertDecoder(AlertInnerDecoder::new()) }
}

/// Error types for network messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// An error consensus decoding a [`VersionMessage`].
    ///
    /// [`VersionMessage`]: super::VersionMessage
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VersionMessageDecoderError(pub(super) VersionMessageDecoderErrorInner);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum VersionMessageDecoderErrorInner {
        /// Error decoding the mandatory prefix of the payload.
        Required(<super::VersionRequiredDecoder as encoding::Decoder>::Error),
        /// Error decoding the sender address and nonce.
        SenderNonce(<super::VersionSenderNonceDecoder as encoding::Decoder>::Error),
        /// Error decoding the user agent.
        UserAgent(UserAgentDecoderError),
        /// Error decoding the start height.
        StartHeight(encoding::UnexpectedEofError),
        /// Error decoding the relay flag.
        Relay(encoding::UnexpectedEofError),
        /// The payload ended somewhere Bitcoin Core would not accept, either inside a field or
        /// before the mandatory prefix was complete.
        UnexpectedEnd,
        /// The payload length declared by the message header does not match the bytes consumed.
        PayloadLength {
            /// Length declared by the message header.
            expected: usize,
            /// Bytes the decoder consumed.
            actual: usize,
        },
    }

    impl From<Infallible> for VersionMessageDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for VersionMessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use VersionMessageDecoderErrorInner as E;

            match &self.0 {
                E::Required(e) => write_err!(f, "version message decoder error"; e),
                E::SenderNonce(e) => write_err!(f, "version message sender/nonce error"; e),
                E::UserAgent(e) => write_err!(f, "version message user agent error"; e),
                E::StartHeight(e) => write_err!(f, "version message start height error"; e),
                E::Relay(e) => write_err!(f, "version message relay error"; e),
                E::UnexpectedEnd => write!(f, "version message payload ended unexpectedly"),
                E::PayloadLength { expected, actual } => write!(
                    f,
                    "version message payload length mismatch, declared {} consumed {}",
                    expected, actual
                ),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for VersionMessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use VersionMessageDecoderErrorInner as E;

            match &self.0 {
                E::Required(e) => Some(e),
                E::SenderNonce(e) => Some(e),
                E::UserAgent(e) => Some(e),
                E::StartHeight(e) => Some(e),
                E::Relay(e) => Some(e),
                E::UnexpectedEnd | E::PayloadLength { .. } => None,
            }
        }
    }

    /// An error decoding a [`UserAgent`] message.
    ///
    /// [`UserAgent`]: super::UserAgent
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UserAgentDecoderError {
        /// Inner decoder error.
        Decoder(<super::UserAgentInnerDecoder as encoding::Decoder>::Error),
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

    /// Errors occurring when decoding a [`RejectReason`].
    ///
    /// [`RejectReason`]: super::RejectReason
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RejectReasonDecoderError {
        /// Inner decoder error.
        Decoder(<encoding::ArrayDecoder<1> as encoding::Decoder>::Error),
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

    /// Errors occurring when decoding a [`Reject`].
    ///
    /// [`Reject`]: super::Reject
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RejectDecoderError {
        /// Inner decoder error.
        Decoder(<super::RejectInnerDecoder as encoding::Decoder>::Error),
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

    /// An error decoding an [`Alert`] message.
    ///
    /// [`Alert`]: super::Alert
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AlertDecoderError(pub(super) <super::AlertInnerDecoder as encoding::Decoder>::Error);

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
}

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
        let version = UserAgentVersion::arbitrary(u)?;

        let mut name: String = u
            .arbitrary::<String>()?
            .chars()
            .filter(|c| !matches!(c, '/' | '(' | ')' | ':'))
            .collect();

        let overhead = 3 + version.to_string().chars().count();
        let max_name = Self::MAX_USER_AGENT_LEN - overhead;
        name.truncate(max_name);

        Ok(Self::new(name, &version))
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

    use hex::hex;

    use super::*;

    #[test]
    fn version_message_test() {
        // This message is from my satoshi node, morning of May 27 2014
        let from_sat = hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001");

        let decode: Result<VersionMessage, _> = encoding::decode_from_slice(&from_sat);
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

        assert_eq!(encoding::encode_to_vec(&real_decode), from_sat);
    }

    #[test]
    fn version_message_without_declared_length_requires_every_field() {
        // The plain `Decode` path has no payload length to work from, so it cannot tell a short
        // payload from a truncated one and keeps requiring all nine fields.
        let mut required = Vec::new();
        required.extend_from_slice(&70_016u32.to_le_bytes());
        required.extend_from_slice(&1u64.to_le_bytes());
        required.extend_from_slice(&1_548_554_224i64.to_le_bytes());
        required.extend_from_slice(&0u64.to_le_bytes());
        required.extend_from_slice(&[0u8; 16]);
        required.extend_from_slice(&8333u16.to_be_bytes());
        assert_eq!(required.len(), 46);

        encoding::decode_from_slice::<VersionMessage>(&required)
            .expect_err("a bare 46 byte payload carries no length context");
    }

    #[test]
    fn reject_message_test() {
        let reject_tx_conflict = hex!("027478121474786e2d6d656d706f6f6c2d636f6e666c69637405df54d3860b3c41806a3546ab48279300affacf4b88591b229141dcf2f47004");
        let reject_tx_nonfinal = hex!("02747840096e6f6e2d66696e616c259bbe6c83db8bbdfca7ca303b19413dc245d9f2371b344ede5f8b1339a5460b");

        let decode_result_conflict: Result<Reject, _> =
            encoding::decode_from_slice(&reject_tx_conflict);
        let decode_result_nonfinal: Result<Reject, _> =
            encoding::decode_from_slice(&reject_tx_nonfinal);

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

        assert_eq!(encoding::encode_to_vec(&conflict), reject_tx_conflict);
        assert_eq!(encoding::encode_to_vec(&nonfinal), reject_tx_nonfinal);
    }

    #[test]
    fn alert_message_test() {
        let alert_hex = hex!("60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c207570677261646520726571756972656400");
        let alert: Alert = encoding::decode_from_slice(&alert_hex).unwrap();
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
