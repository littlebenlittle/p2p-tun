use crate::{Packet, PacketStreamCodec, PacketStreamProtocol, Result};
use libp2p::{
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    identity,
    kad::{store::MemoryStore, Kademlia, KademliaEvent},
    request_response::{ProtocolSupport, RequestResponse, RequestResponseEvent},
    NetworkBehaviour, PeerId,
};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
pub struct Behaviour {
    pub request_response: RequestResponse<PacketStreamCodec>,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
}

impl Behaviour {
    pub fn new(peer_id: PeerId, pub_key: identity::PublicKey) -> Result<Self> {
        Ok(Self {
            request_response: RequestResponse::new(
                PacketStreamCodec {},
                std::iter::once((PacketStreamProtocol {}, ProtocolSupport::Full)),
                Default::default(),
            ),
            kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
            identify: Identify::new(IdentifyConfig::new("ipfs/0.1.0".into(), pub_key)),
        })
    }
}

#[derive(Debug)]
pub enum Event {
    RequestResponse(RequestResponseEvent<Packet, ()>),
    Kademlia(KademliaEvent),
    Identify(IdentifyEvent),
}

impl From<RequestResponseEvent<Packet, ()>> for Event {
    fn from(e: RequestResponseEvent<Packet, ()>) -> Self {
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
