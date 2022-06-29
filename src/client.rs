use crate::{Behaviour, Event, Result, MTU_SIZE};
use async_std::net::{TcpStream, UdpSocket};
use async_tun::{Tun, TunBuilder};
// use bimap::BiMap;
use cidr::Ipv4Cidr;
use etherparse::{InternetSlice, Ipv4HeaderSlice, SlicedPacket, TransportHeader, TransportSlice, Ethernet2Header};
use futures::{prelude::*, select};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use pnet::{
    datalink::{self, NetworkInterface, Channel::Ethernet, DataLinkSender, DataLinkReceiver},
    packet::{
        ethernet::{EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        tcp::MutableTcpPacket,
        udp::MutableUdpPacket,
        MutablePacket, Packet,
    },
    transport::{
        transport_channel, TransportChannelType, TransportProtocol, TransportReceiver,
        TransportSender,
    },
};

use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf, str::FromStr};

/// All the things we need to keep track of
/// for each remote peer
struct Peer {
    id: PeerId,
    /// packets with src addresses in this range
    /// will be forwarded to this peer. None if
    /// client does not forward packets to this
    /// peer
    cidr: Option<Ipv4Cidr>,
    /// sender and receiver for this peer's transport.
    /// None if client does not act as an exit for this
    /// peer
    channel: Option<(TransportSender, TransportReceiver)>,
    /// udp port assigned to peer
    udp_port: u16,
    /// tcp port assigned to peer
    tcp_port: u16,
}

impl Peer {
    fn set_udp_source_port(&self, packet: &mut [u8]) {
        unimplemented!()
    }
    fn set_tcp_source_port(&self, packet: &mut [u8]) {
        unimplemented!()
    }
}

pub struct Client {
    peer_id: PeerId,
    keypair: Keypair,
    /// client's p2p swarm listen address
    listen: Multiaddr,
    tun: Option<Tun>,
    /// metadata about peers
    peers: HashMap<PeerId, Peer>,
    /// ipv4 addresses that have already been looked up
    /// by checking CIDR in Client.peers map
    target: HashMap<Ipv4Addr, PeerId>,
    /// sender for underlying network device
    sender: Box<dyn DataLinkSender>,
    /// receiver for underlying network device
    receiver: Box<dyn DataLinkReceiver>,
    /// ethernet header prepended to ip packets
    ethernet_header: Ethernet2Header,
    /// client's ipv4 address
    ipv4_addr: Ipv4Addr,
}

struct ClientBuilder {
    keypair: Option<Keypair>,
    listen: Option<Multiaddr>,
    network_device: Option<String>,
}

impl ClientBuilder {
    pub fn keypair(self, keypair: Keypair) -> Self {
        Self {
            keypair: Some(keypair),
            listen: self.listen,
            src_mac_addr: self.src_mac_addr,
            dst_mac_addr: self.dst_mac_addr,
        }
    }
    pub fn listen<M: Into<Multiaddr>>(self, listen: M) -> Self {
        Self {
            listen: Some(listen.into()),
            keypair: self.keypair,
            src_mac_addr: self.src_mac_addr,
            dst_mac_addr: self.dst_mac_addr,
        }
    }
    pub fn build(self) -> Option<Client> {
        let keypair = self.keypair?;
        let listen = self.listen?;
        let network_device = {
            let name = self.network_device?;
            datalink::interfaces()
                .into_iter()
                .filter(|iface: &NetworkInterface| iface.name == name)
                .next()?
        };
        // TODO get ipv4_addr, src_mac_addr, and dst_mac_addr,
        // using network device
        let ethernet_header = Ethernet2Header{
            destination: src_mac_addr,
            source: dst_mac_addr,
            ether_type: etherparse::ether_type::IPV4,
        };
        let (sender, receiver) = match datalink::channel(&network_device, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
        };
        Some(Client {
            listen,
            peer_id: keypair.public().to_peer_id(),
            keypair,
            peers: HashMap::new(),
            target: HashMap::new(),
            tun: None,
            ethernet_header,
            ipv4_addr,
            sender,
            receiver,
        })
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            keypair: None,
            listen: None,
            network_device: None,
        }
    }

    pub fn add_peer(&mut self, peer: PeerId, cidr: Option<Ipv4Cidr>) {
        self.peers.insert(
            peer,
            PeerData {
                id: peer,
                cidr,
                channel: None,
            },
        );
    }

    pub fn exit_for(&mut self, peer: PeerId) {
        self.sockets.insert(
            peer,
            ExitIo {
                tcp_streams: Vec::new(),
                udp_socket: None,
            },
        );
    }

    /// the client's own peer id
    pub fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    /// client's p2p swarm address
    pub fn listen(&self) -> Multiaddr {
        self.listen.clone()
    }

    /// if dest address has already associated with a remote
    /// peer id in self.target, return that peer id. Othewise
    /// attempt to match the addr against known peer CIDRs.
    /// If matched, store the result in self.target
    fn get_target(&mut self, dst: &Ipv4Addr) -> Option<&PeerId> {
        self.target.get(dst).or_else(|| {
            for (peer_id, cidr) in &self.peers {
                if cidr.contains(dst) {
                    self.target.insert(*dst, *peer_id);
                    return Some(peer_id);
                }
            }
            None
        })
    }

    /// return the peer id associated with this ipv4 addr. Does
    /// not perform CIDR comparison against known peers
    #[cfg(test)]
    fn get_raw_target(&mut self, dst: &Ipv4Addr) -> Option<&PeerId> {
        self.target.get(dst)
    }

    /// rewrite packet headers to match the client's ip addr and
    /// source port assigned to the given peer
    fn rewrite_packet(&self, peer_id: &PeerId, packet: &mut Vec<u8>) {
        unimplemented!();
    }

    /// modify packet based on source peer and transport protocol
    fn modify_packet(&self, source_peer: &Peer, packet: &mut [u8]) -> Result<()> {
        let sliced_packet = SlicedPacket::from_ip(packet)?;
        match sliced_packet.ip {
            Some(InternetSlice::Ipv4(_, _)) => {
                self.set_ipv4_source_addr(&mut packet);
                match sliced_packet.transport {
                    Some(TransportSlice::Udp(_)) => source_peer.set_udp_source_port(&mut packet),
                    Some(TransportSlice::Tcp(_)) => source_peer.set_tcp_source_port(&mut packet),
                    None => return Err(Error::InvalidTransport),
                }
            }
            Some(protocol) => return Err(Error::UnsupportedProtocol(protocol)),
            None => return Err(Error::InvalidProtocol),
        }
        Ok(())
    }

    /// set the ipv4 packet's source addr to this client's addr
    fn set_ipv4_source_addr(&self, packet: &mut [u8]) {
        unimplemented!()
    }

    /// write ipv4 packet to the underlying network device file
    fn send_ipv4_packet(&mut self, packet: &[u8]) -> Result<()> {
        use etherparse::*;
        let mut ethernet_packet = Vec::<u8>::with_capacity(
            Ethernet2Header::SERIALIZED_SIZE +
            packet.len()
        );
        self.ethernet_header.write(&mut ethernet_packet);
        match self.sender.send_to(&ethernet_packet, None) {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Error::NetworkError(Some(e)),
            None => Error::NetworkError(None)
        }
    }

    /// create virtual TUN device. Requires CAP_MKNOD or
    /// root priveliges. Returns the name of the device
    pub async fn create_tun(&mut self) -> Result<String> {
        // root priveliges unnecessary
        if users::get_current_uid() == 0 {
            return Err(Error::MissingRootPriveliges);
        }
        let tun = TunBuilder::new()
            .name("")
            .tap(false)
            .packet_info(false)
            .up()
            .mtu(MTU_SIZE as i32)
            .try_build()
            .await?;
        self.tun = Some(tun);
        Ok(self.tun.unwrap().name().to_owned())
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // root priveliges unnecessary
        if users::get_effective_uid() == 0 {
            return Err(Error::UnnecessaryRootPriveliges);
        }

        // Client::create_tun should have been run
        // before starting client
        let tun = {
            if let Some(tun) = self.tun {
                tun
            } else {
                return Err(Error::TunNotCreated);
            }
        };

        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen())?;

        // main loop
        let mut packet = [0u8; MTU_SIZE];
        let (mut tun_reader, mut tun_writer) = tun.split();
        loop {
            select! {
                result = tun_reader.read(&mut packet).fuse() => {
                    result?;
                    let dst = get_dest_ipv4_addr(&packet)?.unwrap();
                    if let Some(peer) = self.get_target(&dst) {
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, packet);
                    } else {
                        log::info!("no registered peer for {dst:?}");
                    }
                }
                e = swarm.select_next_some() => match e {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        if let Some(peer_data) = self.peers.get(&peer) {
                            let mut ip_packet = Vec::<u8>::with_capacity(MTU_SIZE);
                            ip_packet.copy_from_slice(&request.0);
                            self.forward_packet(&peer, ip_packet);
                        } else {
                            log::info!("no ip4 addr registered peer {}", peer.to_base58());
                        }
                    }
                    SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received{ peer_id, info })) => {
                        let info: IdentifyInfo = info;
                        let peer_id: PeerId = peer_id;
                        log::info!("peer info received for {}", peer_id.to_base58());
                        if self.peers.contains_key(&peer_id) {
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

fn get_dest_ipv4_addr(packet: &[u8; MTU_SIZE]) -> Result<Option<Ipv4Addr>> {
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
    use etherparse::{PacketBuilder, TransportSlice};

    #[test]
    fn match_ipv4_addr_to_target() {
        // TODO don't use randomness
        let (client, remote_peer) = test_client();
        let dst: Ipv4Addr = "10.1.1.32".parse().unwrap();
        assert_eq!(remote_peer, client.get_target(&dst));
        assert_eq!(remote_peer, client.get_raw_target(&dst));
    }

    #[test]
    fn modify_ip4_udp_packet() {
        let (client, remote_peer) = test_client();

        // build test packet
        let src_addr: Ipv4Addr = "10.1.1.1".parse().unwrap();
        let dst_addr: Ipv4Addr = "51.52.53.54".parse().unwrap();
        let src_port: u16 = 12345;
        let dst_port: u16 = 8080;
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut packet: Vec<u8> = {
            let builder = PacketBuilder::ipv4(
                src_addr.octets(),
                dst_addr.octets(),
                5, // ttl
            )
            .udp(src_port, dst_port);
            let mut serialized = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut serialized, &payload).unwrap();
            serialized
        };

        // rewrite packet headers
        let new_packet = packet.clone();
        client.rewrite_packet(&remote_peer, &mut new_packet);
        let old = SlicedPacket::from_ip(&packet).unwrap();
        let new = SlicedPacket::from_ip(&new_packet).unwrap();

        // verify ip headers
        if let InternetSlice::Ipv4(old_ip, old_ext) = old.ip.unwrap() {
            if let InternetSlice::Ipv4(new_ip, new_ext) = new.ip.unwrap() {
                // source address should be address of client
                assert_eq!(new_ip.source_addr(), client.ipv4_addr());
                // everything else should be the same
                assert_eq!(new_ip.ihl(), old_ip.ihl());
                assert_eq!(new_ip.destination(), old_ip.destination());
                assert_eq!(new_ip.dcp(), old_ip.dcp());
                assert_eq!(new_ip.ecn(), old_ip.ecn());
                assert_eq!(new_ip.identification(), old_ip.identification());
                assert_eq!(new_ip.dont_fragment(), old_ip.dont_fragment());
                assert_eq!(new_ip.fragments_offset(), old_ip.fragments_offset());
                assert_eq!(new_ip.ttl(), old_ip.ttl());
                assert_eq!(new_ip.header_checksum(), old_ip.header_checksum());
                assert_eq!(new_ip.options(), old_ip.options());
            } else {
                assert!(false, "new packet should be ipv4");
            }
        } else {
            panic!("original packet should be ipv4")
        }

        // verify udp headers
        if let TransportSlice::Udp(new_udp) = old.transport.unwrap() {
            if let TransportSlice::Udp(old_udp) = new.transport.unwrap() {
                // source port should match port assigned to remote peer
                assert_eq!(old_udp.source_port(), client.udp_port(&remote_peer));
                // destination port should be the same
                assert_eq!(old_udp.destination_port(), new_udp.destination_port());
            } else {
                assert!(false, "new transport should be udp");
            }
        }

        // verify payload
        assert_eq!(old.payload, new.payload);
    }

    fn test_client() -> (Client, PeerId) {
        // TODO don't rely on randomness
        let client = Client::default();
        let remote_peer = Keypair::generate_ed25519().public().to_peer_id();
        let cidr = {
            let start_addr = "10.1.1.0".parse().unwrap();
            let mask = 24;
            Ipv4Cidr::new(start_addr, mask).unwrap()
        };
        client.add_peer(remote_peer, cidr);
        (client, remote_peer)
    }
}
