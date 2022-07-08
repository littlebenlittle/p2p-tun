use crate::{Behaviour, Destination, Event, PacketRequest, Port, Result, MTU};
use async_std::{
    fs::File,
    io::{BufReader, BufWriter},
};
use async_tun::{Tun, TunBuilder};
// use bimap::BiMap;
use cidr::Ipv4Cidr;
use futures::io::{Sink};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        tcp::{MutableTcpPacket, TcpPacket},
        udp::{MutableUdpPacket, UdpPacket},
        MutablePacket, Packet,
    },
    transport::{
        transport_channel, TransportChannelType::Layer3, TransportReceiver, TransportSender,
        tcp_packet_iter,
    },
};

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::{Arc,Mutex},
};

#[derive(Debug)]
pub enum Error {
    NoPeerRegisteredForIpv4Addr,
    UnnecessaryRootPriveliges,
    UnsupportedInternetProtocol,
    UnsupportedTransportProtocol,
    UnknownPeer,
    NoMatchCidr,
    InvalidIpPacket,
    InvalidTcpPacket,
    InvalidUdpPacket,
    NoMatchingSocket,
    NoMatchingPort,
}

impl std::error::Error for Error {}

//TODO
impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NoPeerRegisteredForIpv4Addr => {
                fmt.write_str("no peer registered for ipv4 address")
            }
        }
    }
}

struct Peer {
    id: PeerId,
    /// tcp ports on local machine for rewriting packets sent to network
    exit_tcp_ports: HashMap<(Ipv4Addr, Port), Port>,
    /// incoming TUN packets matching any CIDR will be sent to the
    /// associated peer
    forward_cidrs: Vec<Ipv4Cidr>,
    /// packets received on p2p transport will be
    /// sent to the network if they match any of the
    /// associated CIDRs
    exit_cidrs: Vec<Ipv4Cidr>,
}

impl Peer {
    fn get_exit_tcp_port(&self, svc_addr: &Ipv4Addr, svc_port: &Port) -> Result<&Port> {
        match self.exit_tcp_ports.get(&(*svc_addr, *svc_port)) {
            Some(socket) => Ok(socket),
            None => Err(Box::new(Error::NoMatchingPort)),
        }
    }
}

//TODO check for conflicting forward CIDRs between peers
pub struct Client {
    peer_id: PeerId,
    keypair: Keypair,
    /// client's p2p swarm listen address
    listen: Multiaddr,
    peers: HashMap<PeerId, Peer>,
    /// packets sent from the network through an exit
    /// to this peer will be given this ipv4 source address
    ipv4_addr: Ipv4Addr,
    /// ipv4 address of the client on the local network
    network_ipv4_addr: Ipv4Addr,
    /// sender for network device that client will send tcp packets to
    /// when acting as an exit
    tcp_tx: Mutex<TransportSender>,
    /// receiver for network device that client will receive packets from
    /// when acting as an exit
    tcp_rx: Mutex<TransportReceiver>,
    /// peers known to be associated with a given ipv4 forward addr
    cached_ipv4_peer: HashMap<Ipv4Addr, PeerId>,
    /// peers and daddrs we know we are acting as an exit for
    cached_should_exit: HashSet<(PeerId, Ipv4Addr)>,
    /// user that client will run as after creating
    /// network device file handles
    user: users::User,
    /// socket addresses associated with remote tcp service
    local_tcp_sockets: HashMap<(Ipv4Addr, Port), (Ipv4Addr, Port)>,
    tun: Tun,
    // writer for TUN device
    //tun_tx: BufWriter<&'a File>,
    // reader for TUN device
    //tun_rx: BufReader<&'a File>,
}

struct ClientBuilder {
    keypair: Option<Keypair>,
    listen: Option<Multiaddr>,
    user: Option<String>,
    ipv4_addr: Option<Ipv4Addr>,
}

impl ClientBuilder {
    /// set the keypair of p2p swarm peer
    pub fn keypair(self, keypair: Keypair) -> Self {
        Self {
            keypair: Some(keypair),
            listen: self.listen,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
        }
    }

    /// set the listen address of p2p swarm
    pub fn listen<M: Into<Multiaddr>>(self, listen: M) -> Self {
        Self {
            listen: Some(listen.into()),
            keypair: self.keypair,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
        }
    }

    /// set the user that p2p swarm will run as
    pub fn user(self, user: String) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: Some(user),
            ipv4_addr: self.ipv4_addr,
        }
    }

    /// set the ipv4 dest address for packets sent to
    /// the TUN device
    pub fn ipv4_addr(self, ipv4_addr: Ipv4Addr) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: self.user,
            ipv4_addr: Some(ipv4_addr),
        }
    }

    pub async fn build(self) -> Option<Client> {
        let keypair = self.keypair?;
        let listen = self.listen?;
        let user = users::get_user_by_name(&self.user?)?;
        let ipv4_addr = self.ipv4_addr?;
        // create TUN device
        let tun = match TunBuilder::new()
            .name("")
            .tap(false)
            .packet_info(false)
            .up()
            .mtu(MTU as i32)
            .try_build()
            .await
        {
            Ok(tun) => tun,
            Err(e) => return None,
        };
        let network_ipv4_addr: Ipv4Addr = {
            // TODO get ipv4 address from tcp channel
            "127.0.0.1".parse().unwrap()
        };
        let (mut tun_rx, mut tun_tx) = tun.split();
        Some(Client {
            listen,
            peer_id: keypair.public().to_peer_id(),
            keypair,
            user,
            ipv4_addr,
            peers: HashMap::new(),
            cached_ipv4_peer: HashMap::new(),
            cached_should_exit: HashSet::new(),
            local_tcp_sockets: HashMap::new(),
            tun,
            network_ipv4_addr,
        })
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            keypair: None,
            listen: None,
            user: None,
            ipv4_addr: None,
        }
    }

    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        forward_cidrs: Vec<Ipv4Cidr>,
        exit_cidrs: Vec<Ipv4Cidr>,
    ) {
        self.peers.insert(
            peer_id,
            Peer {
                id: peer_id,
                exit_tcp_ports: HashMap::new(),
                forward_cidrs,
                exit_cidrs,
            },
        );
    }

    fn get_local_tcp_socket(
        &self,
        svc_addr: &Ipv4Addr,
        svc_port: &Port,
    ) -> Result<&(Ipv4Addr, Port)> {
        match self.local_tcp_sockets.get(&(*svc_addr, *svc_port)) {
            Some(socket) => Ok(socket),
            None => Err(Box::new(Error::NoMatchingSocket)),
        }
    }

    /// get the peer id associated with this ipv4 address.
    /// Returns none if no peer has a CIDR that matches
    /// the address
    fn get_ipv4_peer(&mut self, daddr: &Ipv4Addr) -> Option<&PeerId> {
        // check if we've cached this ip addr
        if let Some(peer_id) = self.cached_ipv4_peer.get(daddr) {
            return Some(peer_id);
        }
        // otherwise look for cidr match
        for (peer_id, peer) in &mut self.peers {
            let mut found = false;
            for cidrs in peer.forward_cidrs {
                for cidr in cidrs {
                    if cidr.contains(daddr) {
                        self.cached_ipv4_peer.insert(*daddr, *peer_id);
                        found = true;
                        break;
                    }
                }
            }
            if found {
                return Some(peer_id);
            }
        }
        return None;
    }

    /// determine whether we act as an exit for packets
    /// originating from the given peer and destined
    /// for the given address
    fn should_exit(&self, peer_id: &PeerId, dst_addr: &Ipv4Addr) -> bool {
        // check if we've cached this ip addr
        if self.cached_should_exit.contains(&(*peer_id, *dst_addr)) {
            return true;
        }
        // otherwise look for cidr match
        if let Some(peer) = self.peers.get(peer_id) {
            for cidrs in peer.forward_cidrs {
                for cidr in cidrs {
                    if cidr.contains(dst_addr) {
                        self.cached_should_exit.insert((*peer_id, *dst_addr));
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// handle a packet destined for the network
    fn handle_network_packet<'b>(
        &self,
        peer_id: &PeerId,
        packet: &mut [u8],
        tcp_tx: TransportSender,
    ) -> Result<()> {
        let ipv4_packet = match MutableIpv4Packet::new(packet) {
            Some(p) => p,
            None => return Err(Box::new(Error::InvalidIpPacket))
        };
        let daddr = ipv4_packet.get_destination();
        if !self.should_exit(&peer_id, &daddr) {
            return Err(Box::new(Error::NoMatchCidr));
        }
        ipv4_packet.set_source(self.network_ipv4_addr);
        match ipv4_packet.get_next_level_protocol() {
            Tcp => {
                let mut tcp_packet = match MutableTcpPacket::new(ipv4_packet.payload_mut()) {
                    Some(p) => p,
                    None => return Err(Box::new(Error::InvalidTcpPacket)),
                };
                let dport = tcp_packet.get_destination();
                let peer = self.peers.get(&peer_id).unwrap();
                let sport = peer.get_exit_tcp_port(&daddr, &dport)?;
                tcp_packet.set_source(*sport);
                tcp_tx.send_to(ipv4_packet, IpAddr::V4(daddr));
            }
            _ => return Err(Box::new(Error::UnsupportedTransportProtocol)),
        }
        Ok(())
    }

    /// handle a packet destined for the local TUN
    async fn handle_tun_packet<'b>(
        &mut self,
        peer_id: &PeerId,
        packet: &mut [u8],
    ) -> Result<()> {
        use pnet::packet::ip::IpNextHeaderProtocols::{Tcp, Udp};
        let mut ipv4_packet = match MutableIpv4Packet::new(packet) {
            Some(p) => p,
            None => return Err(Box::new(Error::InvalidIpPacket))
        };
        // source address of the remote service
        let saddr = ipv4_packet.get_source();
        let daddr = match ipv4_packet.get_next_level_protocol() {
            Tcp => {
                let mut tcp_packet = match MutableTcpPacket::new(ipv4_packet.payload_mut()) {
                    Some(p) => p,
                    None => return Err(Box::new(Error::InvalidTcpPacket)),
                };
                // source port of the remote service socket
                let sport = tcp_packet.get_source();
                let (daddr, dport) = self.get_local_tcp_socket(&saddr, &sport)?;
                tcp_packet.set_destination(*dport);
                daddr
            }
            _ => return Err(Box::new(Error::UnsupportedTransportProtocol)),
        };
        ipv4_packet.set_destination(*daddr);
        use futures::{io::AsyncWriteExt};
        self.tun.writer().write(&ipv4_packet.packet()).await;
        Ok(())
    }

    // process a packet received from a peer on p2p transport
    async fn process_peer_packet(
        &mut self,
        peer_id: &PeerId,
        mut request: PacketRequest,
    ) -> Result<()> {
        match request.destination() {
            Destination::Net => {
                let tcp_tx_mxg = self.tcp_tx.lock().unwrap();
                let tcp_tx = *tcp_tx_mxg;
                self.handle_network_packet(&peer_id, request.payload_mut(), tcp_tx)
            },
            Destination::Tun => self.handle_tun_packet(&peer_id, request.payload_mut()).await,
        }
    }

    /// process a packet received on TUN device
    fn process_tun_packet(&mut self, packet: Vec<u8>, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        use pnet::packet::ip::IpNextHeaderProtocols::{Tcp, Udp};
        let ipv4_packet = match Ipv4Packet::new(&packet) {
            Some(p) => p,
            None => return Err(Box::new(Error::InvalidIpPacket)),
        };
        // address of remote service socket
        let daddr = ipv4_packet.get_destination();
        let peer_id: &PeerId = match self.get_ipv4_peer(&daddr) {
            Some(peer_id) => peer_id,
            None => return Err(Box::new(Error::NoMatchCidr)),
        };
        // address of local socket
        let saddr = ipv4_packet.get_source();
        match ipv4_packet.get_next_level_protocol() {
            Tcp => {
                let tcp_packet = match TcpPacket::new(&mut ipv4_packet.payload()) {
                    Some(p) => p,
                    None => return Err(Box::new(Error::InvalidTcpPacket)),
                };
                // port of local socket
                let sport = tcp_packet.get_source();
                // port of remote service socket
                let dport = tcp_packet.get_destination();
                // TODO this runs for every packet; needs benchmark
                self.local_tcp_sockets
                    .insert((daddr, dport), (saddr, sport));
            }
            _ => return Err(Box::new(Error::UnsupportedTransportProtocol)),
        }
        swarm.behaviour_mut().request_response.send_request(
            &peer_id,
            PacketRequest {
                payload: ipv4_packet.packet().to_vec(),
                destination: Destination::Net,
            },
        );
        Ok(())
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // drop root privileges
        users::switch::set_effective_uid(self.user.uid())?;

        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen.clone())?;

        // TODO use threads until pnet supports async
        let (mut tcp_packet_tx, mut tcp_packet_rx) = std::sync::mpsc::channel::<TcpPacket>();
        let tcp_packet_tx_mutex = Mutex::new(tcp_packet_tx);
        let (mut tcp_tx, mut tcp_rx) = match transport_channel(1500, Layer3(IpNextHeaderProtocols::Tcp)) {
            Ok(t) => t,
            Err(e) => return Err(Box::new(e)),
        };
        std::thread::spawn(move || {
            let tcp_packet_tx_mx_guard = tcp_packet_tx_mutex.lock().unwrap();
            let tcp_packet_tx = *tcp_packet_tx_mx_guard;
            let iter = tcp_packet_iter(&mut tcp_rx);
            loop {
                match iter.next() {
                    Ok((packet, addr)) => {
                        tcp_packet_tx.send(packet);
                    },
                    Err(e) => {
                        log::error!("failed to receive on tcp transport")
                    }
                }
            }
        });

        // main loop
        let mut buf = [0u8; MTU];
        let mut tun_reader = self.tun.reader();
        loop {
            use futures::{select, prelude::*};
            select! {
                nbytes = tun_reader.read(&mut buf).fuse() => {
                    let nbytes: usize = nbytes?;
                    let mut packet = Vec::<u8>::with_capacity(nbytes);
                    packet.copy_from_slice(&buf);
                    self.process_tun_packet(packet, &mut swarm);
                }
                e = swarm.select_next_some() => match e {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        self.process_peer_packet(&peer, request).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {}
}
