use crate::{PacketRequest, PacketStreamCodec, PacketStreamProtocol, Result};
use libp2p::{
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    identity,
    kad::{store::MemoryStore, Kademlia, KademliaEvent},
    mdns::{Mdns, MdnsEvent},
    ping,
    request_response::{ProtocolSupport, RequestResponse, RequestResponseEvent},
    NetworkBehaviour, PeerId,
};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
pub struct Behaviour {
    pub request_response: RequestResponse<PacketStreamCodec>,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub mdns: Mdns,
    pub ping: ping::Behaviour,
}

impl Behaviour {
    pub async fn new(peer_id: PeerId, pub_key: identity::PublicKey) -> Result<Self> {
        Ok(Self {
            request_response: RequestResponse::new(
                PacketStreamCodec {},
                std::iter::once((PacketStreamProtocol {}, ProtocolSupport::Full)),
                Default::default(),
            ),
            kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
            identify: Identify::new(IdentifyConfig::new("ipfs/0.1.0".into(), pub_key)),
            mdns: Mdns::new(Default::default()).await?,
            ping: ping::Behaviour::new(ping::Config::new().with_keep_alive(true)),
        })
    }
}

#[derive(Debug)]
pub enum Event {
    RequestResponse(RequestResponseEvent<Vec<u8>, ()>),
    Kademlia(KademliaEvent),
    Identify(IdentifyEvent),
    Mdns(MdnsEvent),
    Ping(ping::Event)
}

impl From<RequestResponseEvent<Vec<u8>, ()>> for Event {
    fn from(e: RequestResponseEvent<Vec<u8>, ()>) -> Self {
        Self::RequestResponse(e)
    }
}

impl From<KademliaEvent> for Event {
    fn from(e: KademliaEvent) -> Self {
        Self::Kademlia(e)
    }
}

impl From<IdentifyEvent> for Event {
    fn from(e: IdentifyEvent) -> Self {
        Self::Identify(e)
    }
}

impl From<MdnsEvent> for Event {
    fn from(e: MdnsEvent) -> Self {
        Self::Mdns(e)
    }
}

impl From<ping::Event> for Event {
    fn from(e: ping::Event) -> Self {
        Self::Ping(e)
    }
}
