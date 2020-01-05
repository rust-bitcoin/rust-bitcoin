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

//! Network message
//!
//! This module defines the `Message` traits which are used
//! for (de)serializing Bitcoin objects for transmission on the network. It
//! also defines (de)serialization routines for many primitives.
//!

use std::{io, iter, mem, fmt};
use std::borrow::Cow;
use std::io::Cursor;

use blockdata::block;
use blockdata::transaction;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use network::message_filter;
use consensus::encode::{CheckedData, Decodable, Encodable, VarInt};
use consensus::{encode, serialize};
use consensus::encode::MAX_VEC_SIZE;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl From<&'static str> for CommandString {
    fn from(f: &'static str) -> Self {
        CommandString(f.into())
    }
}

impl From<String> for CommandString {
    fn from(f: String) -> Self {
        CommandString(f.into())
    }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Encodable for CommandString {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        s: S,
    ) -> Result<usize, encode::Error> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        if strbytes.len() > 12 {
            return Err(encode::Error::UnrecognizedNetworkCommand(self.0.clone().into_owned()));
        }
        for x in 0..strbytes.len() {
            rawbytes[x] = strbytes[x];
        }
        rawbytes.consensus_encode(s)
    }
}

impl Decodable for CommandString {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(d)?;
        let rv = iter::FromIterator::from_iter(
            rawbytes
                .iter()
                .filter_map(|&u| if u > 0 { Some(u as char) } else { None })
        );
        Ok(CommandString(rv))
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A Network message
pub struct RawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(Vec<(u32, Address)>),
    /// `inv`
    Inv(Vec<message_blockdata::Inventory>),
    /// `getdata`
    GetData(Vec<message_blockdata::Inventory>),
    /// `notfound`
    NotFound(Vec<message_blockdata::Inventory>),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(transaction::Transaction),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(Vec<block::BlockHeader>),
    /// `sendheaders`
    SendHeaders,
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    // TODO: bloom filtering
    /// BIP157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// `alert`
    Alert(Vec<u8>),
    /// `reject`
    Reject(message_network::Reject)
}

impl NetworkMessage {
    /// Return the message command. This is useful for debug outputs.
    pub fn cmd(&self) -> &'static str {
        match *self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack     => "verack",
            NetworkMessage::Addr(_)    => "addr",
            NetworkMessage::Inv(_)     => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool    => "mempool",
            NetworkMessage::Tx(_)      => "tx",
            NetworkMessage::Block(_)   => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::GetAddr    => "getaddr",
            NetworkMessage::Ping(_)    => "ping",
            NetworkMessage::Pong(_)    => "pong",
            NetworkMessage::GetCFilters(_) => "getcfilters",
            NetworkMessage::CFilter(_) => "cfilter",
            NetworkMessage::GetCFHeaders(_) => "getcfheaders",
            NetworkMessage::CFHeaders(_) => "cfheaders",
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt",
            NetworkMessage::CFCheckpt(_) => "cfcheckpt",
            NetworkMessage::Alert(_)    => "alert",
            NetworkMessage::Reject(_)    => "reject",
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        self.cmd().into()
    }
}

impl RawNetworkMessage {
    /// Return the message command. This is useful for debug outputs.
    pub fn cmd(&self) -> &'static str {
        self.payload.cmd()
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

struct HeaderSerializationWrapper<'a>(&'a Vec<block::BlockHeader>);

impl<'a> Encodable for HeaderSerializationWrapper<'a> {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(&mut s)?;
        for header in self.0.iter() {
            len += header.consensus_encode(&mut s)?;
            len += 0u8.consensus_encode(&mut s)?;
        }
        Ok(len)
    }
}

impl Encodable for RawNetworkMessage {
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(&mut s)?;
        len += self.command().consensus_encode(&mut s)?;
        len += CheckedData(match self.payload {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat)    => serialize(dat),
            NetworkMessage::Inv(ref dat)     => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat)      => serialize(dat),
            NetworkMessage::Block(ref dat)   => serialize(dat),
            NetworkMessage::Headers(ref dat) => serialize(&HeaderSerializationWrapper(dat)),
            NetworkMessage::Ping(ref dat)    => serialize(dat),
            NetworkMessage::Pong(ref dat)    => serialize(dat),
            NetworkMessage::GetCFilters(ref dat) => serialize(dat),
            NetworkMessage::CFilter(ref dat) => serialize(dat),
            NetworkMessage::GetCFHeaders(ref dat) => serialize(dat),
            NetworkMessage::CFHeaders(ref dat) => serialize(dat),
            NetworkMessage::GetCFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::CFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::Alert(ref dat)    => serialize(dat),
            NetworkMessage::Reject(ref dat) => serialize(dat),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr => vec![],
        }).consensus_encode(&mut s)?;
        Ok(len)
    }
}

struct HeaderDeserializationWrapper(Vec<block::BlockHeader>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let byte_size = (len as usize)
                            .checked_mul(mem::size_of::<block::BlockHeader>())
                            .ok_or(encode::Error::ParseFailed("Invalid length"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(encode::Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
            if u8::consensus_decode(&mut d)? != 0u8 {
                return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }
}

impl Decodable for RawNetworkMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode(&mut d)?;
        let cmd = CommandString::consensus_decode(&mut d)?.0;
        let raw_payload = CheckedData::consensus_decode(&mut d)?.0;

        let mut mem_d = Cursor::new(raw_payload);
        let payload = match &cmd[..] {
            "version" => NetworkMessage::Version(Decodable::consensus_decode(&mut mem_d)?),
            "verack"  => NetworkMessage::Verack,
            "addr"    => NetworkMessage::Addr(Decodable::consensus_decode(&mut mem_d)?),
            "inv"     => NetworkMessage::Inv(Decodable::consensus_decode(&mut mem_d)?),
            "getdata" => NetworkMessage::GetData(Decodable::consensus_decode(&mut mem_d)?),
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode(&mut mem_d)?),
            "getblocks" => NetworkMessage::GetBlocks(Decodable::consensus_decode(&mut mem_d)?),
            "getheaders" => NetworkMessage::GetHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "mempool" => NetworkMessage::MemPool,
            "block"   => NetworkMessage::Block(Decodable::consensus_decode(&mut mem_d)?),
            "headers" => NetworkMessage::Headers(
                HeaderDeserializationWrapper::consensus_decode(&mut mem_d)?.0
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping"    => NetworkMessage::Ping(Decodable::consensus_decode(&mut mem_d)?),
            "pong"    => NetworkMessage::Pong(Decodable::consensus_decode(&mut mem_d)?),
            "tx"      => NetworkMessage::Tx(Decodable::consensus_decode(&mut mem_d)?),
            "getcfilters" => NetworkMessage::GetCFilters(Decodable::consensus_decode(&mut mem_d)?),
            "cfilter" => NetworkMessage::CFilter(Decodable::consensus_decode(&mut mem_d)?),
            "getcfheaders" => NetworkMessage::GetCFHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "cfheaders" => NetworkMessage::CFHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(Decodable::consensus_decode(&mut mem_d)?),
            "cfcheckpt" => NetworkMessage::CFCheckpt(Decodable::consensus_decode(&mut mem_d)?),
            "reject" => NetworkMessage::Reject(Decodable::consensus_decode(&mut mem_d)?),
            "alert"   => NetworkMessage::Alert(Decodable::consensus_decode(&mut mem_d)?),
            _ => return Err(encode::Error::UnrecognizedNetworkCommand(cmd.into_owned())),
        };
        Ok(RawNetworkMessage {
            magic: magic,
            payload: payload
        })
    }
}

#[cfg(test)]
mod test {
    use std::io;
    use super::{RawNetworkMessage, NetworkMessage, CommandString};
    use network::constants::ServiceFlags;
    use consensus::encode::{Encodable, deserialize, deserialize_partial, serialize};
    use hex::decode as hex_decode;
    use hashes::sha256d::Hash;
    use hashes::Hash as HashTrait;
    use network::address::Address;
    use super::message_network::{Reject, RejectReason, VersionMessage};
    use network::message_blockdata::{Inventory, GetBlocksMessage, GetHeadersMessage};
    use blockdata::block::{Block, BlockHeader};
    use network::message_filter::{GetCFilters, CFilter, GetCFHeaders, CFHeaders, GetCFCheckpt, CFCheckpt};
    use blockdata::transaction::Transaction;

    fn hash(slice: [u8;32]) -> Hash {
        Hash::from_slice(&slice).unwrap()
    }

    #[test]
    fn full_round_ser_der_raw_network_message_test() {
        // TODO: Impl Rand traits here to easily generate random values.
        let version_msg: VersionMessage = deserialize(&hex_decode("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001").unwrap()).unwrap();
        let tx: Transaction = deserialize(&hex_decode("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap()).unwrap();
        let block: Block = deserialize(&hex_decode("000000202aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d7490600000000000010bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e5503bd5750d4061a4ed90a700f010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a3983704012000000000000000000000000000000000000000000000000000000000000000000000000001000000017e4f81175332a733e26d4ba4e29f53f67b7a5d7c2adebb276e447ca71d130b55000000006b483045022100cac809cd1a3d9ad5d5e31a84e2e1d8ec5542841e4d14c6b52e8b38cbe1ff1728022064470b7fb0c2efeccb2e84bfa36ec5f9e434c84b1101c00f7ee32f726371b7410121020e62280798b6b8c37f068df0915b0865b63fabc401c2457cbc3ef96887dd3647ffffffff02ca2f780c000000001976a914c6b5545b3592cb477d709896fa705592c9b6113a88ac663b2a06000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac0000000001000000011e99f5a785e677e017d36b50aa4fd10010ffd039f38f42f447ca8895250e121f01000000d90047304402200d3d296ad641a281dd5c0d68b9ab0d1ad5f7052bec148c1fb81fb1ba69181ec502201a372bb16fb8e054ee9bef41e300d292153830f841a4db0ab7f7407f6581b9bc01473044022002584f313ae990236b6bebb82fbbb006a2b02a448dd5c93434428991eae960d60220491d67d2660c4dde19025cf86e5164a559e2c79c3b98b40e146fab974acd24690147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9140ffdcf96700455074292a821c74922e8652993998788997bc60000000017a9148ce5408cfeaddb7ccb2545ded41ef478109454848700000000010000000113100b09e6a78d63ec4850654ab0f68806de29710b09172eddfef730652b155501000000da00473044022015389408e3446a3f36a05060e0e4a3c8b92ff3901ba2511aa944ec91a537a1cb022045a33b6ec47605b1718ed2e753263e54918edbf6126508ff039621fb928d28a001483045022100bb952fde81f216f7063575c0bb2bedc050ce08c96d9b437ea922f5eb98c882da02201b7cbf3a2f94ea4c5eb7f0df3af2ebcafa8705af7f410ab5d3d4bac13d6bc6120147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914d3db9a20312c3ab896a316eb108dbd01e47e17d687e0ba7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000016e3cca1599cde54878e2f27f434df69df0afd1f313cb6e38c08d3ffb57f97a6c01000000da0048304502210095623b70ec3194fa4037a1c1106c2580caedc390e25e5b330bbeb3111e8184bc02205ae973c4a4454be2a3a03beb66297143c1044a3c4743742c5cdd1d516a1ad3040147304402202f3d6d89996f5b42773dd6ebaf367f1af1f3a95c7c7b487ec040131c40f4a4a30220524ffbb0b563f37b3eb1341228f792e8f84111b7c4a9f49cdd998e052ee42efa0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9141ade6b95896dde8ec4dee9e59af8849d3797348e8728af7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000011d9dc3a5df9b5b2eeb2bd11a2db243be9e8cc23e2f180bf317d32a499904c15501000000db00483045022100ebbd1c9a8ce626edbb1a7881df81e872ef8c6424feda36faa8a5745157400c6a02206eb463bc8acd5ea06a289e86115e1daae0c2cf10d9cbbd199e1311170d5543ef01483045022100809411a917dc8cf4f3a777f0388fdea6de06243ef7691e500c60abd1c7f19ae602205255d2b1191d8adedb77b814ccb66471eb8486cb4ff8727824254ee5589f176b0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914759a49c772347be81c49517f9e1e6def6a88d4dd87800b85c60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704f0000006a47304402201be0d485f6a3ce871be80064c593c5327b3fd7e450f05ab7fae38385bc40cfbe02206e2a6c9970b5d1d10207892376733757486634fce4f352e772149c486857612101210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704e0000006b483045022100ccc8c0ac90bdb0402842aec91830c765cdead7a728552a6a34de7d13a6dab28e02206c96f8640cf3444054e9632b197be30598a09c3d5defcd95750bdb922a60d64801210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000011b436669c06cbf3442e21a2fe3edc20cd3cf13c358c53234bc4d88bfd8c4bd2a000000006a47304402204a63410ee13db52c7609ab08e25b7fe3c608cc21cc1755ad13460685eb55193202204cd1ea80c06a81571119be0b8cccd96ef7cdd90f62c1fe2d538622feb08e22ba0121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d64523365345261445653324d436a736e536171734a5753324465655446624238354541794a4d5843784c7934000000000100000001be4a95ed36316cada5118b1982e4cb4a07f93e7a4153e227466f1cb0776de995000000006b483045022100a22d5251deea0470806bab817013d675a63cd52218d6e477ab0c9d601d018b7f022042121b46afcdcd0c66f189398212b66085e88c6973ae560f1810c13e55e2bee40121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d57484d57504e5248515872504c7338554c586b4d483746745356413675366b5a6b4a4e3851796e4e583751340000000001000000016c061a65b49edec21acdbc22f97dc853aa872302aeef13fabf0bf6807de1b8bd010000006b483045022100dd80381f2d158b4dad7f98d2d97317c533fb36e737542473feb05fa74d0b73bb02207097d4331196069167e525b61d132532292fd75cc039a5839c04c2545d427e2b0121035e9a597df8b417bef66811882a2844604fc591c427f642628f0fef46be19a4c9feffffff0280a4bf07000000001976a914573b9106e16ee0b5c143dc40f0724f77dd0e282088ac9533b22c000000001976a9149c4da607efb1d759d33da71778bc6cafa56acb5988acd31b0e0001000000017dae20994b69b28534e5b22f3d7c50f9d7541348cbf6f43fcc654263ebaf8f68000000006b483045022100a85300eb94b24b044877d0b0d61e08e16dbc82ec7d69c723a8a45519f95c35b002203d78376e6bee31b455c097557af7fe4d6b620bc74269e9a75e2aad2b545abddb012103b0d08aba2a5ac6cf2788fda941c386040e35e49d3a57d2aefb16c0438fb98acbfeffffff022222305f000000001976a914cfda30dd836b596db6a9c230c45ae2179107f04888ac80a4bf07000000001976a91442dfcf5823aacb185844e663873c35fb98bfd21b88acd31b0e000100000002ad3e85e4af30678a330f8941ed7a9ca17cd0236368d238cac4e9ff09c466fed1020000006b483045022100d1196c48a0392e09592f1b96b4aec32ab0cecb6fd17b1d0c85ab3250a2fe45d9022059217c82f684fcdecdbe660a2077ea956dfbbb964d2648bc1e8ae0f0fe565449012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff34f0a71c1c2cd610522e9c18c67931cded5e9647d4419c49b99715e2a0795f3d020000006a4730440220316e81d8242abf3c5f885d200feca12c3adb63cf2cd4dc74602f7b8b0cba50340220210d525758df77ccdca6908311c1895275e07bbb29b45963a19252acde55873f012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff0510270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788ac10270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788aca0860100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac70110100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac0000000000000000026a000000000001000000018e33fecc2ddbd86c5ea919f7bd5a5acf8a09f3e0cdaaaf4f08c5ef095161ef1100000000fdfe0000483045022100d2489b225d39b7d8b6767a6928c8029a2a1297c08fdf00d683ba0c1987e7d7000220176cb66c8a243806bb7421f658325a69a51c82c0c3314e37f2400f33626390210148304502210096cfa57662a545830d0e29610becd41ea031e256339913718ce18dbb1a27bdb00220482911c851d15adcd37097dff99a9ff1f97d953bcebc528835118f447412553e014c695221028d9889862b29430278c084b5c4090b7b807b31e047bcd212ebc2c4e43fc0e3c52103160949a7c8c81f2c25d7763f57eb1cb407d867c5b7c290331bd2dc4b1182c6d32103fbef3b60914bda9173765902013a251ec89450c75d0b5a96a143db1dabf98d9553aeffffffff0220e8891c0100000017a914d996715e081c50f8f6b1b4e7fb6ca214f9924fdf87809698000000000017a9145611d812263f32960228cb5f85329bce4770a218870000000001000000017720507dcbe6c69f652b0c0ce19406f482372d1a8abc05d45fb7acf97fb80eec00000000fdfe00004830450221009821d8e117de44b1202c829c0f5063997acf007cf9b561c6fb8d1212cddb6c40022010ff5067b0d9d4eca2da0ceb876e9a16f1a2142da866d3042a7bae8968813e8001483045022100dea759d14a8a1c5da5f3dcc5509871aaa2c1e3be03752c1b858d80fa4227163702205183d70cc28dcb6df9b037714c8b6442ef84e0ddce07711a30c731e9f0925090014c695221028d70ea66fe7a7def282df7b2b498007e5072933e42c18f63ce85975dcbcf1a8821037e8f842b1e47e21d88002c5aab2559212a4c2c9dbe5ef5347f2a29afd0510ec1210251259cb9fd4f6206488408286e4475c9c9fe887e57a3e32ae4da222778a2aedf53aeffffffff023380cb020000000017a9143b5a7e85b22656a34d43187ac8dd09acd7109d2487809698000000000017a914b9b4b555f594a34deec3ad61d5c5f3738b17ee158700000000").unwrap()).unwrap();
        let header: BlockHeader = deserialize(&hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b").unwrap()).unwrap();

        let msgs = vec![
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(vec![(45, Address::new(&([123,255,000,100], 833).into(), ServiceFlags::NETWORK))]),
            NetworkMessage::Inv(vec![Inventory::Block(hash([8u8; 32]).into())]),
            NetworkMessage::GetData(vec![Inventory::Transaction(hash([45u8; 32]).into())]),
            NetworkMessage::NotFound(vec![Inventory::Error]),
            NetworkMessage::GetBlocks(GetBlocksMessage::new(vec![hash([1u8; 32]).into(), hash([4u8; 32]).into()], hash([5u8; 32]).into())),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![hash([10u8; 32]).into(), hash([40u8; 32]).into()], hash([50u8; 32]).into())),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(tx),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(vec![header]),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(15),
            NetworkMessage::Pong(23),
            NetworkMessage::GetCFilters(GetCFilters{filter_type: 2, start_height: 52, stop_hash: hash([42u8; 32]).into()}),
            NetworkMessage::CFilter(CFilter{filter_type: 7, block_hash: hash([25u8; 32]).into(), filter: vec![1,2,3]}),
            NetworkMessage::GetCFHeaders(GetCFHeaders{filter_type: 4, start_height: 102, stop_hash: hash([47u8; 32]).into()}),
            NetworkMessage::CFHeaders(CFHeaders{filter_type: 13, stop_hash: hash([53u8; 32]).into(), previous_filter: hash([12u8; 32]).into(), filter_hashes: vec![hash([4u8; 32]).into(), hash([12u8; 32]).into()]}),
            NetworkMessage::GetCFCheckpt(GetCFCheckpt{filter_type: 17, stop_hash: hash([25u8; 32]).into()}),
            NetworkMessage::CFCheckpt(CFCheckpt{filter_type: 27, stop_hash: hash([77u8; 32]).into(), filter_headers: vec![hash([3u8; 32]).into(), hash([99u8; 32]).into()]}),
            NetworkMessage::Alert(vec![45,66,3,2,6,8,9,12,3,130]),
            NetworkMessage::Reject(Reject{message: "Test reject".into(), ccode: RejectReason::Duplicate, reason: "Cause".into(), hash: hash([255u8; 32])}),
        ];

        for msg in msgs {
            let raw_msg = RawNetworkMessage {magic: 57, payload: msg};
            assert_eq!(deserialize::<RawNetworkMessage>(&serialize(&raw_msg)).unwrap(), raw_msg);
        }

    }

    #[test]
    fn serialize_commandstring_test() {
        let cs = CommandString("Andrew".into());
        assert_eq!(serialize(&cs), vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);

        // Test oversized one.
        let mut encoder = io::Cursor::new(vec![]);
        assert!(CommandString("AndrewAndrewA".into()).consensus_encode(&mut encoder).is_err());
    }

    #[test]
    fn deserialize_commandstring_test() {
        let cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), "Andrew".into());

        let short_cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
    }

    #[test]
    fn serialize_verack_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Verack }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                                  0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_ping_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Ping(100) }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                                  0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }


    #[test]
    fn serialize_mempool_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::MemPool }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                                  0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_getaddr_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                                  0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn deserialize_getaddr_test() {
        let msg = deserialize(
            &[0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
        let preimage = RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr };
        assert!(msg.is_ok());
        let msg : RawNetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_version_test() {
        let msg = deserialize::<RawNetworkMessage>(
            &[  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
                0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
                0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
                0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
                0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
                0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01 ]);

        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message_test() {
        let data = [  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0, 0 ];
        let msg = deserialize_partial::<RawNetworkMessage>(&data);
        assert!(msg.is_ok());

        let (msg, consumed) = msg.unwrap();
        assert_eq!(consumed, data.to_vec().len() - 2);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }
}
