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
    private_key: Vec<u8>,
    peer_id: PeerId,
    listen: Multiaddr,
    peers: Vec<VpnPeer>,
    user: String,
}

impl Config {
    pub fn private_key(&mut self) -> Result<Keypair, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Keypair::Ed25519(
            libp2p::identity::ed25519::Keypair::decode(&mut self.private_key)?,
        ))
    }
    #[allow(dead_code)]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    pub fn peers(&self) -> Vec<VpnPeer> {
        self.peers.clone()
    }
    pub fn listen(&self) -> Multiaddr {
        self.listen.clone()
    }
    pub fn user(&self) -> &str {
        &*self.user
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut id_keys = ed25519::Keypair::generate();
        let peer_id = Keypair::Ed25519(id_keys.clone()).public().to_peer_id();
        let peers = Vec::new();
        let listen = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
        let private_key = ed25519::Keypair::encode(&mut id_keys).to_vec();
        Self {
            peer_id,
            private_key,
            peers,
            listen,
            user: "p2ptun".to_owned(),
        }
    }
}
