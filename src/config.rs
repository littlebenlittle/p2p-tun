use base58::{FromBase58, FromBase58Error, ToBase58};
use bimap::BiBTreeMap;
use cidr::{Ipv4Cidr, errors::NetworkParseError};
use libp2p::{
    identity::{ed25519, error::DecodingError, Keypair},
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, BTreeMap}, net::Ipv4Addr, str::FromStr};

use crate::PeerRoutingTable;

type Result<T> = std::result::Result<T, Error>;

const PB_BASE58_KEYLEN: usize = 68;

#[derive(Clone, Serialize, Deserialize)]
pub struct VpnPeer {
    pub ip4_addr: Ipv4Addr,
    pub peer_id: PeerId,
    pub swarm_addr: Option<Multiaddr>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// protobuf encoding of keypair
    keypair: String,
    peer_id: PeerId,
    swarm_addr: Multiaddr,
    user: String,
    peer_routing_table: BTreeMap<String, PeerId>,
    /// kademlia bootstrap peers
    bootaddrs: HashMap<PeerId, Multiaddr>,
}

impl Config {
    pub fn keypair(&self) -> Result<Keypair> {
        keypair_from_base58_proto(&self.keypair)
    }
    pub fn peer_routing_table(&self) -> Result<PeerRoutingTable>  {
        let mut rt = BiBTreeMap::new();
        for (cidr, peer_id) in &self.peer_routing_table {
            rt.insert(Ipv4Cidr::from_str(&cidr)?, *peer_id);
        }
        Ok(PeerRoutingTable(rt))
    }
    pub fn swarm_addr(&self) -> Multiaddr {
        self.swarm_addr.clone()
    }
    pub fn user(&self) -> &str {
        &self.user
    }
    pub fn bootaddrs(&self) -> &HashMap<PeerId, Multiaddr> {
        &self.bootaddrs
    }
}

#[derive(Debug)]
pub enum Error {
    FromBase58Error(FromBase58Error),
    InvalidKeyLength(usize),
    DecodingError(DecodingError),
    NetworkParseError(NetworkParseError),
}

impl From<FromBase58Error> for Error {
    fn from(e: FromBase58Error) -> Self {
        Self::FromBase58Error(e)
    }
}

impl From<DecodingError> for Error {
    fn from(e: DecodingError) -> Self {
        Self::DecodingError(e)
    }
}

impl From<NetworkParseError> for Error {
    fn from(e: NetworkParseError) -> Self {
        Self::NetworkParseError(e)
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodingError(e) => write!(f, "decoding error: {e}"),
            Self::FromBase58Error(e) => write!(f, "base58 error: {e:?}"),
            Self::NetworkParseError(e) => write!(f, "network parse error: {e}"),
            Self::InvalidKeyLength(len) => write!(f, "invalid key length: expected {PB_BASE58_KEYLEN}, got {len}"),
        }
    }
}

pub fn keypair_from_base58_proto(keypair: &str) -> Result<Keypair> {
    let keypair_bytes = keypair.from_base58()?;
    match keypair_bytes.len() {
        PB_BASE58_KEYLEN => Ok(Keypair::from_protobuf_encoding(&keypair_bytes)?),
        len => Err(Error::InvalidKeyLength(len)),
    }
}

impl Default for Config {
    fn default() -> Self {
        let id_keys = ed25519::Keypair::generate();
        let peer_id = libp2p::identity::Keypair::Ed25519(id_keys.clone())
            .public()
            .to_peer_id();
        Self {
            keypair: Keypair::Ed25519(id_keys)
                .to_protobuf_encoding()
                .expect("keypair should encode")
                .to_base58(),
            peer_id,
            peer_routing_table: {
                let mut rt = BTreeMap::new();
                rt.insert("0.0.0.0/0".to_owned(), PeerId::random());
                rt
            },
            swarm_addr: "/ip4/127.0.0.1/tcp/5555".parse().unwrap(),
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
