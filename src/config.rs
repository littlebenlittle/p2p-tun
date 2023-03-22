use libp2p::{
    identity::{ed25519, Keypair},
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, ops::Mul, str::FromStr};

#[derive(Clone, Serialize, Deserialize)]
pub struct VpnPeer {
    pub ip4_addr: Ipv4Addr,
    pub peer_id: PeerId,
    pub swarm_addr: Option<Multiaddr>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// protobuf encoding of keypair
    keypair: Vec<u8>,
    peer_id: PeerId,
    listen: Multiaddr,
    peers: Vec<VpnPeer>,
    user: String,
    /// kademlia bootstrap peers
    bootaddrs: HashMap<PeerId, Multiaddr>
}

impl Config {
    pub fn keypair(&self) -> Keypair {
        Keypair::from_protobuf_encoding(&self.keypair).expect("keypair to decode")
    }
    #[allow(dead_code)]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
    pub fn peers(&self) -> &Vec<VpnPeer> {
        &self.peers
    }
    pub fn listen(&self) -> &Multiaddr {
        &self.listen
    }
    pub fn user(&self) -> &str {
        &self.user
    }
    pub fn bootaddrs(&self) -> &HashMap<PeerId, Multiaddr> {
        &self.bootaddrs
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
            keypair: Keypair::Ed25519(id_keys)
                .to_protobuf_encoding()
                .expect("keypair should encode"),
            peer_id,
            peers,
            listen,
            user: "p2ptun".to_owned(),
            bootaddrs: {
                let mut bootaddrs = HashMap::new();
                for peer in [
                    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
                    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
                    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
                ] {
                    bootaddrs.insert(
                        PeerId::from_str(peer).unwrap(),
                        Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io").unwrap(),
                    );
                }
                bootaddrs
            },
        }
    }
}
