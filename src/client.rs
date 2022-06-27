use crate::{Behaviour, Event, Packet, Result, PACKET_LEN};
use async_tun::{Tun, TunBuilder};
use bimap::BiMap;
use cidr::Ipv4Cidr;
use etherparse::{InternetSlice, Ipv4HeaderSlice, SlicedPacket, TransportHeader};
use futures::{prelude::*, select};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

pub struct Client {
    peer_id: PeerId,
    keypair: Keypair,
    listen: Multiaddr,
    user: users::User,
    /// mapping between peer ids and CIDRs
    peers: BiMap<PeerId, Ipv4Cidr>,
    /// ipv4 addresses that have already been looked up
    /// by checking CIDR in Client.peers map
    target: BiMap<PeerId, Ipv4Addr>,
}

impl Default for Client {
    fn default() -> Self {
        let keypair = Keypair::generate_ed25519();
        let user = users::get_user_by_name("p2ptun").expect("user does not exist");
        Self {
            peer_id: keypair.public().to_peer_id(),
            peers: BiMap::new(),
            target: BiMap::new(),
            listen: "/ip4/0.0.0.0/udp/0".parse().unwrap(),
            keypair,
            user,
        }
    }
}

struct ClientBuilder {
    keypair: Option<Keypair>,
    listen: Option<Multiaddr>,
    user: Option<users::User>,
}

impl ClientBuilder {
    pub fn keypair(self, keypair: Keypair) -> Self {
        Self {
            keypair: Some(keypair),
            listen: self.listen,
            user: self.user,
        }
    }
    pub fn listen<M: Into<Multiaddr>>(self, listen: M) -> Self {
        Self {
            listen: Some(listen.into()),
            keypair: self.keypair,
            user: self.user,
        }
    }
    pub fn user(self, username: &str) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: users::get_user_by_name(username),
        }
    }
    pub fn build(self) -> Option<Client> {
        let keypair = self.keypair?;
        let listen = self.listen?;
        let user = self.user?;
        Some(Client {
            listen,
            user,
            peer_id: keypair.public().to_peer_id(),
            keypair,
            peers: BiMap::new(),
            target: BiMap::new(),
        })
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            keypair: None,
            listen: None,
            user: None,
        }
    }

    pub fn add_peer(&mut self, peer: PeerId, cidr: Ipv4Cidr) {
        self.peers.insert(peer, cidr);
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub fn listen(&self) -> Multiaddr {
        self.listen.clone()
    }

    /// if dest address has already associated with a remote
    /// peer id in self.target, return that peer id. Othewise
    /// attempt to match the addr against known peer CIDRs.
    /// If matched, store the result in self.target
    fn get_target(&mut self, dst: &Ipv4Addr) -> Option<&PeerId> {
        self.target.get_by_right(dst).or_else(|| {
            for (peer_id, cidr) in &self.peers {
                if cidr.contains(dst) {
                    self.target.insert(*peer_id, *dst);
                    return Some(peer_id);
                }
            }
            None
        })
    }

    /// return the peer id associated with this ipv4 addr. Does
    /// not perform CIDR comparison against known peers
    fn get_raw_target(&mut self, dst: &Ipv4Addr) -> Option<&PeerId> {
        self.target.get_by_right(dst)
    }

    pub async fn run(&mut self) -> Result<()> {
        // create TUN device
        assert_eq!(
            users::get_current_uid(),
            0,
            "must be root to create TUN device"
        );
        let tun = create_tun().await?;
        let name = tun.name().to_owned();

        // drop root priveliges
        users::switch::set_effective_uid(self.user.uid())?;
        assert_ne!(
            users::get_effective_uid(),
            0,
            "insecure to be root; should switch to unpriveliged user"
        );

        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen())?;

        // main loop
        let mut packet = [0u8; PACKET_LEN];
        let (mut tun_reader, mut tun_writer) = tun.split();
        loop {
            select! {
                result = tun_reader.read(&mut packet).fuse() => {
                    result?;
                    let dst = get_dest_ipv4_addr(&packet)?.unwrap();
                    if let Some(peer_id) = self.get_target(&dst) {
                        let peer_id: &PeerId = peer_id;
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer_id, Packet(packet.clone()));
                    } else {
                        log::info!("no registered peer for {dst:?}");
                    }
                }
                e = swarm.select_next_some() => match e {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        let peer_id: PeerId = peer;
                        if let Some(peer_data) = self.peers.get_by_left(&peer_id) {
                            let mut ip_packet = request.0;
                            self.rewrite_packet(&mut packet);
                            peer_data.socket.write(&packet).await?;
                        } else {
                            log::info!("no ip4 addr registered peer {}", peer.to_base58());
                        }
                    }
                    SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received{ peer_id, info })) => {
                        let info: IdentifyInfo = info;
                        let peer_id: PeerId = peer_id;
                        log::info!("peer info received for {}", peer_id.to_base58());
                        if self.peers.contains_left(&peer_id) {
                            log::info!("adding peer addresses and dialing");
                            for addr in info.listen_addrs {
                                log::info!("{addr}");
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            }
                            swarm.dial(peer_id)?;
                        } else {
                            log::info!("unknown peer; skipping")
                        }
                    }
                    SwarmEvent::Behaviour(_) => {}
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("now listening on {address:?}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        log::info!("established connection to {}", peer_id.to_base58());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        log::info!("closed connection to {}", peer_id.to_base58());
                    }
                    e => log::info!("{e:?}"),
                }
            }
        }
    }
}

async fn make_swarm(id_keys: &Keypair) -> Result<Swarm<Behaviour>> {
    let pub_key = id_keys.public();
    let peer_id = PeerId::from(pub_key.clone());
    let transport = development_transport(id_keys.clone()).await?;
    let mut behaviour = Behaviour::new(peer_id, pub_key)?;
    let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    for peer in [
        "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    ] {
        behaviour
            .kademlia
            .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
    }
    Ok(Swarm::new(transport, behaviour, peer_id))
}

async fn create_tun() -> Result<Tun> {
    TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .up()
        .mtu(PACKET_LEN as i32)
        .try_build()
        .await
}

fn get_dest_ipv4_addr(packet: &[u8; PACKET_LEN]) -> Result<Option<Ipv4Addr>> {
    let sp: SlicedPacket = SlicedPacket::from_ip(packet)?;
    match sp.ip.unwrap() {
        InternetSlice::Ipv4(header_slice, extension_slice) => {
            Ok(Some(header_slice.destination_addr()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_ipv4_addr_to_target() {
        // TODO don't use randomness
        let client = Client::default();
        let remote_peer = Keypair::generate_ed25519().public().to_peer_id();
        let cidr = {
            let start_addr = "10.1.1.1".parse().unwrap();
            Ipv4Cidr::new(start_addr, 24).unwrap()
        };
        client.add_peer(remote_peer, cidr);
        let dst: Ipv4Addr = "10.1.1.32".parse().unwrap();
        assert_eq!(remote_peer, client.get_target(&dst));
        assert_eq!(remote_peer, client.get_raw_target(&dst));
    }

    #[test]
    fn modify_ip4_udp_packet() {
        use etherparse::{PacketBuilder, TransportSlice};
        // TODO don't use randomness
        let client = Client::default();
        let remote_peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut packet: Vec<u8> = {
            let builder = PacketBuilder::ipv4(
                [10, 1, 1, 1], // src ip
                [10, 1, 2, 1], // dst ip
                5,             // ttl
            )
            .udp(23456, 8080);
            let payload = [1, 2, 3, 4, 5, 6, 7, 8];
            let mut serialized = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut serialized, &payload).unwrap();
            serialized
        };
        client.rewrite_packet(&mut packet);
        let sp = SlicedPacket::from_ip(&packet);
        assert!(sp.is_ok());
        let sp = sp.unwrap();
        assert!(sp.ip.is_some());
        match sp.ip.unwrap() {
            InternetSlice::Ipv4(value, extensions) => {}
            InternetSlice::Ipv6(_, _) => assert!(false, "got ipv6 when ipv4 expected"),
        }
        assert!(sp.transport.is_some());
        match sp.transport.unwrap() {
            TransportSlice::Udp(value) => {
                assert_eq!(value.source_port(), 23456);
                assert_eq!(value.destination_port(), 8080);
            }
            TransportSlice::Tcp(_) => assert!(false, "got tcp when udp expected"),
        }
    }
}
