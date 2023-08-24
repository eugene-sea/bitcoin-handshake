use std::{
    cmp,
    io::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::SystemTime,
};

use async_trait::async_trait;
use bitcoin::{
    consensus::{encode, Decodable, Encodable},
    network::{
        constants::{ServiceFlags, PROTOCOL_VERSION},
        message::{NetworkMessage, RawNetworkMessage},
        message_network::VersionMessage,
        Address, Magic,
    },
};
use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::trace;

/// Bitcoin message header length in bytes
const HEADER_LENGTH: usize = 24;
/// Max expected payload length of message
const MAX_PAYLOAD_LENGTH: usize = 1024;

#[derive(Debug, thiserror::Error)]
enum BitcoinP2pError {
    #[error("encoding error")]
    EncodeError(#[from] encode::Error),
    #[error("I/O error")]
    IoError(#[from] io::Error),
    #[error("payload length exceeded maximum size: {0}")]
    TooLongPayload(usize),
    #[error("unexpected message `{unexpected}`, but expected `{expected}`")]
    UnexpectedMessage {
        unexpected: &'static str,
        expected: &'static str,
    },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("bad nonce: {0}")]
    BadNonce(u64),
    #[error("bad magic: {0}")]
    BadMagic(Magic),
}

struct BitcoinNetworkMessageCodec {
    magic: Magic,
    max_payload_length: usize,
}

impl Decoder for BitcoinNetworkMessageCodec {
    type Item = NetworkMessage;
    type Error = BitcoinP2pError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HEADER_LENGTH {
            return Ok(None);
        }

        let payload_length =
            u32::from_le_bytes(src[16..20].try_into().expect("Can read payload length")) as usize;

        if payload_length > self.max_payload_length {
            return Err(BitcoinP2pError::TooLongPayload(payload_length));
        }

        let header_and_payload_length = payload_length + HEADER_LENGTH;
        src.reserve(header_and_payload_length);

        if src.len() < header_and_payload_length {
            return Ok(None);
        }

        let mut reader = src.split_to(header_and_payload_length).reader();

        let message = RawNetworkMessage::consensus_decode_from_finite_reader(&mut reader)?;
        if message.magic != self.magic {
            return Err(BitcoinP2pError::BadMagic(message.magic));
        }
        Ok(Some(message.payload))
    }
}

impl Encoder<NetworkMessage> for BitcoinNetworkMessageCodec {
    type Error = BitcoinP2pError;

    fn encode(&mut self, message: NetworkMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let raw_message = RawNetworkMessage {
            magic: self.magic,
            payload: message,
        };
        raw_message.consensus_encode(&mut dst.writer())?;
        Ok(())
    }
}

#[async_trait]
trait BitcoinP2pCommunicationChannel {
    async fn write_message(&mut self, message: NetworkMessage) -> Result<(), BitcoinP2pError>;
    async fn read_message(&mut self) -> Result<NetworkMessage, BitcoinP2pError>;
}

/// Makes handshake with other node. If `accept` is `true` we accept
/// handshake, otherwise we initiate
async fn handshake<C>(
    mut channel: C,
    accept: bool,
    version: VersionMessage,
    min_version: u32,
) -> Result<(C, u32), BitcoinP2pError>
where
    C: BitcoinP2pCommunicationChannel,
{
    let nonce = version.nonce;
    let our_version = version.version;
    if !accept {
        channel
            .write_message(NetworkMessage::Version(version.clone()))
            .await?;
        trace!(?version, "Sent version");
    }

    let their_version = match channel.read_message().await? {
        NetworkMessage::Version(v) => v,
        msg => {
            return Err(BitcoinP2pError::UnexpectedMessage {
                unexpected: msg.cmd(),
                expected: "version",
            })
        }
    };
    trace!(?their_version, "Received version");

    if their_version.version < min_version {
        return Err(BitcoinP2pError::UnsupportedVersion(their_version.version));
    }

    if their_version.nonce == nonce {
        return Err(BitcoinP2pError::BadNonce(their_version.nonce));
    }

    if accept {
        channel
            .write_message(NetworkMessage::Version(version.clone()))
            .await?;
        trace!(?version, "Sent version");
    } else {
        channel.write_message(NetworkMessage::Verack).await?;
        trace!(?their_version, "Sent verack");
    }

    match channel.read_message().await? {
        NetworkMessage::Verack => {}
        msg => {
            return Err(BitcoinP2pError::UnexpectedMessage {
                unexpected: msg.cmd(),
                expected: "verack",
            })
        }
    }
    trace!(?their_version, "Received verack");

    if accept {
        channel.write_message(NetworkMessage::Verack).await?;
        trace!(?their_version, "Sent verack");
    }

    let negotiated_version = cmp::min(our_version, their_version.version);
    trace!(%negotiated_version, "Handshake completed");
    Ok((channel, negotiated_version))
}

struct BitcoinPeer {
    framed: Framed<TcpStream, BitcoinNetworkMessageCodec>,
}

impl BitcoinPeer {
    pub async fn connect<A>(
        addr: A,
        codec: BitcoinNetworkMessageCodec,
    ) -> Result<Self, BitcoinP2pError>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        let framed = Framed::new(stream, codec);
        Ok(Self { framed })
    }
}

#[async_trait]
impl BitcoinP2pCommunicationChannel for BitcoinPeer {
    async fn write_message(&mut self, message: NetworkMessage) -> Result<(), BitcoinP2pError> {
        self.framed.send(message).await
    }

    async fn read_message(&mut self) -> Result<NetworkMessage, BitcoinP2pError> {
        if let Some(message) = self.framed.next().await {
            Ok(message?)
        } else {
            Err(BitcoinP2pError::IoError(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was closed",
            )))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BitcoinP2pError> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Can set default subscriber");

    let peer = BitcoinPeer::connect(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444),
        BitcoinNetworkMessageCodec {
            magic: Magic::REGTEST,
            max_payload_length: MAX_PAYLOAD_LENGTH,
        },
    )
    .await?;
    handshake(
        peer,
        false,
        VersionMessage::new(
            ServiceFlags::NONE,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Can get duration since epoch")
                .as_secs() as i64,
            Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                ServiceFlags::NONE,
            ),
            Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                ServiceFlags::NONE,
            ),
            rand::random(),
            "test-agent".to_owned(),
            0,
        ),
        PROTOCOL_VERSION,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        join,
        sync::mpsc::{channel, Receiver, Sender},
        time::timeout,
    };
    use tracing_test::traced_test;

    use super::*;

    #[test]
    fn bitcoin_network_message_codec_encode_decode() {
        let mut codec = BitcoinNetworkMessageCodec {
            magic: Magic::BITCOIN,
            max_payload_length: MAX_PAYLOAD_LENGTH,
        };
        let mut bytes = BytesMut::new();
        let msg = NetworkMessage::Ping(7);

        codec
            .encode(msg.clone(), &mut bytes)
            .expect("Can encode message");

        let msg_decoded = codec
            .decode(&mut bytes)
            .expect("Can decode message")
            .expect("Message is present");

        assert_eq!(msg, msg_decoded);
    }

    #[derive(Debug)]
    struct TestBitcoinP2pCommunicationChannel {
        sender: Sender<NetworkMessage>,
        receiver: Receiver<NetworkMessage>,
    }

    #[async_trait]
    impl BitcoinP2pCommunicationChannel for TestBitcoinP2pCommunicationChannel {
        async fn write_message(&mut self, message: NetworkMessage) -> Result<(), BitcoinP2pError> {
            self.sender.send(message).await.expect("Can send");
            Ok(())
        }

        async fn read_message(&mut self) -> Result<NetworkMessage, BitcoinP2pError> {
            Ok(self.receiver.recv().await.ok_or_else(|| {
                BitcoinP2pError::IoError(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Channel was closed",
                ))
            })?)
        }
    }

    fn create_test_channels() -> (
        TestBitcoinP2pCommunicationChannel,
        TestBitcoinP2pCommunicationChannel,
    ) {
        let (sender_1, receiver_1) = channel(1);
        let (sender_2, receiver_2) = channel(1);
        (
            TestBitcoinP2pCommunicationChannel {
                sender: sender_1,
                receiver: receiver_2,
            },
            TestBitcoinP2pCommunicationChannel {
                sender: sender_2,
                receiver: receiver_1,
            },
        )
    }

    fn create_version_message(version: u32, nonce: u64) -> VersionMessage {
        VersionMessage {
            version,
            ..VersionMessage::new(
                ServiceFlags::NONE,
                1,
                Address::new(
                    &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                    ServiceFlags::NONE,
                ),
                Address::new(
                    &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                    ServiceFlags::NONE,
                ),
                nonce,
                "test-agent".to_owned(),
                1,
            )
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn handshake_initiate_accept() {
        let (channel_1, channel_2) = create_test_channels();
        let version_1 = timeout(
            Duration::from_secs(1),
            handshake(channel_1, true, create_version_message(6, 1), 6),
        );
        let version_2 = timeout(
            Duration::from_secs(1),
            handshake(channel_2, false, create_version_message(7, 2), 6),
        );

        let (version_1, version_2) = join!(version_1, version_2);
        let (_, version_1) = version_1
            .expect("No timeout")
            .expect("Can accept handshake");
        let (_, version_2) = version_2
            .expect("No timeout")
            .expect("Can initiate handshake");

        assert_eq!(version_1, 6);
        assert_eq!(version_2, 6);
    }

    #[tokio::test]
    #[traced_test]
    async fn handshake_wrong_version() {
        let (channel_1, channel_2) = create_test_channels();
        let version_1 = timeout(
            Duration::from_secs(1),
            handshake(channel_1, true, create_version_message(6, 1), 6),
        );
        let version_2 = timeout(
            Duration::from_secs(1),
            handshake(channel_2, false, create_version_message(7, 2), 7),
        );

        let (_, version_2) = join!(version_1, version_2);
        let error = version_2
            .expect("No timeout")
            .expect_err("Expected version error");

        assert!(matches!(error, BitcoinP2pError::UnsupportedVersion(6)));
    }

    #[tokio::test]
    #[traced_test]
    async fn handshake_wrong_nonce() {
        let (channel_1, channel_2) = create_test_channels();
        let version_1 = timeout(
            Duration::from_secs(1),
            handshake(channel_1, true, create_version_message(6, 1), 6),
        );
        let version_2 = timeout(
            Duration::from_secs(1),
            handshake(channel_2, false, create_version_message(7, 1), 6),
        );

        let (version_1, _) = join!(version_1, version_2);
        let error = version_1
            .expect("No timeout")
            .expect_err("Expected nonce error");

        assert!(matches!(error, BitcoinP2pError::BadNonce(1)));
    }
}
