use libp2p::{
    identity::{ed25519, Keypair},
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Serialize, Deserialize)]
pub struct VpnPeer {
    pub ip: Ipv4Addr,
    pub peer_id: PeerId,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// protobuf encoding of keypair
    keypair: Vec<u8>,
    peer_id: PeerId,
    listen: Multiaddr,
    peers: Vec<VpnPeer>,
    addr: Ipv4Addr,
    user: String,
}

impl Config {
    pub fn keypair(&self) -> Keypair {
        Keypair::from_protobuf_encoding(&self.keypair).expect("keypair to decode")
    }
    #[allow(dead_code)]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }
    pub fn peers(&self) -> Vec<VpnPeer> {
        self.peers.clone()
    }
    pub fn listen(&self) -> Multiaddr {
        self.listen.clone()
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.addr.clone()
    }
    pub fn user(&self) -> &str {
        &self.user
    }
}

impl Default for Config {
    fn default() -> Self {
        let id_keys = ed25519::Keypair::generate();
        let peer_id = libp2p::identity::Keypair::Ed25519(id_keys.clone())
            .public()
            .to_peer_id();
        let peers = Vec::new();
        let listen = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
        Self {
            keypair: Keypair::Ed25519(id_keys).to_protobuf_encoding().expect("keypair should encode"),
            peer_id,
            peers,
            listen,
            addr: "192.168.1.1".parse().unwrap(),
            user: "p2p-tun".to_owned()
        }
    }
}
