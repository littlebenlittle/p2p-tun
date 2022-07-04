use crate::{Behaviour, Event, Packet, Port, Result, MTU};
use async_std::net::{SocketAddr, TcpStream, UdpSocket};
use async_tun::{Tun, TunBuilder};
// use bimap::BiMap;
use cidr::Ipv4Cidr;
use etherparse::{
    InternetSlice, IpNumber, Ipv4Header, Ipv4HeaderSlice, SlicedPacket, TcpHeaderSlice,
    TransportSlice, UdpHeaderSlice, {TcpHeader, UdpHeader},
};
use futures::{
    future::{select_all, try_join_all},
    prelude::*,
    select,
};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};

use std::{
    collections::{HashMap, VecDeque},
    io::Result as IoResult,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    str::FromStr,
};

#[derive(Debug)]
pub enum Error {
    NoPeerRegisteredForIpv4Addr,
    UnnecessaryRootPriveliges,
    TunNotCreated,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NoPeerRegisteredForIpv4Addr => {
                fmt.write_str("no peer registered for ipv4 address")
            }
            Error::TunNotCreated => fmt.write_str(
                "tun device hasn't been created; use client.create_tun() before calling run()",
            ),
        }
    }
}

struct Peer {
    tcp_streams: HashMap<(Ipv4Addr, Port), TcpStream>,
    udp_sockets: HashMap<(Ipv4Addr, Port), UdpSocket>,
}

//TODO check for conflicting forward CIDRs between peers
pub struct Client {
    peer_id: PeerId,
    keypair: Keypair,
    /// client's p2p swarm listen address
    listen: Multiaddr,
    peers: HashMap<PeerId, Peer>,
    /// incoming TUN packets matching any CIDR will be sent to the
    /// associated peer
    forward_cidrs: HashMap<PeerId, Vec<Ipv4Cidr>>,
    /// peers known to be associated with a given ipv4 forward addr
    cached_ipv4_peer: HashMap<Ipv4Addr, PeerId>,
    /// packets received on p2p transport matching will be
    /// sent to the network if they match any of the
    /// associated CIDRs
    exit_cidrs: HashMap<PeerId, Vec<Ipv4Cidr>>,
    user: users::User,
}

struct ClientBuilder {
    keypair: Option<Keypair>,
    listen: Option<Multiaddr>,
    user: Option<String>,
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
    pub fn user(self, user: String) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: Some(user),
        }
    }

    pub fn build<'a>(self) -> Option<Client> {
        let keypair = self.keypair?;
        let listen = self.listen?;
        let user = users::get_user_by_name(&self.user?)?;
        Some(Client {
            listen,
            peer_id: keypair.public().to_peer_id(),
            keypair,
            user,
            peers: HashMap::new(),
            cached_ipv4_peer: HashMap::new(),
            exit_cidrs: HashMap::new(),
            forward_cidrs: HashMap::new(),
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

    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        forward_cidr: Vec<Ipv4Cidr>,
        exit_cidr: Vec<Ipv4Cidr>,
    ) {
        self.peers.insert(
            peer_id,
            Peer {
                tcp_streams: HashMap::new(),
                udp_sockets: HashMap::new(),
            },
        );
    }

    /// return the open tcp stream associated with this
    /// peer, dst addr, and dst port, creating one if
    /// it does not exit
    async fn get_tcp_stream(
        &mut self,
        peer_id: &PeerId,
        dst_addr: &Ipv4Addr,
        dst_port: &Port,
    ) -> Result<&mut TcpStream> {
        // TODO maybe macro?
        if let Some(peer) = self.peers.get_mut(peer_id) {
            // check if we already opened a tcp stream for this peer, addr, port
            if let Some(tcp_stream) = peer.tcp_streams.get_mut(&(*dst_addr, *dst_port)) {
                return Ok(tcp_stream);
            }
            // check if we are acting as an exit for this peer on this addr
            for cidrs in self.exit_cidrs.get(peer_id) {
                for cidr in cidrs {
                    if cidr.contains(dst_addr) {
                        let tcp_stream = TcpStream::connect((*dst_addr, *dst_port)).await?;
                        self.tcp_streams.push(tcp_stream);
                        peer.tcp_streams.insert((*dst_addr, *dst_port), &tcp_stream);
                        return Ok(&mut tcp_stream);
                    }
                }
            }
            return Err(Box::new(Error::NoMatchCidr));
        }
        Err(Box::new(Error::UnknownPeer))
    }

    /// return the open udp socket associated with this
    /// peer, listen addr, and listen port, creating one if
    /// it does not exit
    async fn get_udp_socket(
        &mut self,
        peer_id: &PeerId,
        addr: &Ipv4Addr,
        port: &Port,
    ) -> Result<&mut UdpSocket> {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            // check if we already opened a tcp stream for this peer, addr, port
            if let Some(tcp_stream) = peer.udp_sockets.get_mut(&(*addr, *port)) {
                return Ok(tcp_stream);
            }
            // check if we are acting as an exit for this peer on this addr
            for cidrs in self.exit_cidrs.get(peer_id) {
                for cidr in cidrs {
                    if cidr.contains(addr) {
                        let udp_socket = UdpSocket::bind((*addr, *port)).await?;
                        self.udp_sockets.push(udp_socket);
                        peer.udp_sockets.insert((*addr, *port), &udp_socket);
                        return Ok(&mut udp_socket);
                    }
                }
            }
            return Err(Box::new(Error::NoMatchCidr));
        }
        Err(Box::new(Error::UnknownPeer))
    }

    /// get the peer with a CIDR that matches the given
    /// destination IP address
    pub fn get_peer(&self, dst_addr: &Ipv4Addr) -> Option<PeerId> {
        // check if we've cached this ip addr
        if let Some(peer) = self.cached_ipv4_peer.get(dst_addr) {
            return Some(*peer);
        }
        // otherwise look for cidr match
        for (peer, cidrs) in self.forward_cidrs {
            for cidr in cidrs {
                if cidr.contains(dst_addr) {
                    return Some(peer);
                }
            }
        }
        None
    }

    /// process a packet received on TUN device
    fn process_tun_packet(&mut self, packet: Packet, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        if let Some(peer) = self.get_peer(packet.daddr()) {
            swarm.behaviour_mut().request_response.send_request(
                &peer,
                packet,
            );
            Ok(())
        } else {
            Err(Box::new(Error::NoPeerRegisteredForIpv4Addr))
        }
    }

    // process a packet received from a peer on p2p transport
    async fn process_peer_packet(&self, peer: &PeerId, packet: &Packet) -> Result<()> {
        match packet {
            // outgoing packets are written to the appopriate socket
            Packet::Out { transport, payload } => match transport {
                Transport::Tcp { daddr, dport, .. } => {
                    let tcp_stream = self.get_tcp_stream(peer, &daddr, &dport).await?;
                    tcp_stream.send(payload).await
                }
                Transport::Udp { daddr, dport, .. } => {
                    let udp_socket = self.get_udp_socket(peer, &daddr, &dport).await?;
                    udp_socket
                        .send_to(payload.as_slice(), (*daddr, *dport))
                        .await;
                }
                _ => return Err(Box::new(Error::UnsupportedProtocol)),
            },
            // incoming packets are written to the TUN if they
            // they match the peer's incoming CIDRs
            Packet::In { transport, payload } => {
                let ip_packet = match transport {
                    Transport::Tcp { .. } => {
                        let ip_packet = Vec::<u8>::with_capacity(
                            Ipv4Header::SERIALIZED_SIZE
                                + TcpHeader::SERIALIZED_SIZE
                                + payload.len(),
                        );
                        let ip_header = Ipv4Header::new(
                            (TcpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                            20,
                            IpNumber::Tcp,
                            saddr.octets(),
                            // TODO is this the right daddr?
                            self.ipv4_addr.octets(),
                        );
                        ip_header.write(&mut ip_packet);
                        ip_packet
                    }
                    Transport::Udp { .. } => {
                        let ip_packet = Vec::<u8>::with_capacity(
                            Ipv4Header::SERIALIZED_SIZE
                                + UdpHeader::SERIALIZED_SIZE
                                + payload.len(),
                        );
                        let ip_header = Ipv4Header::new(
                            (UdpHeader::SERIALIZED_SIZE + payload.len()) as u16,
                            20,
                            IpNumber::Udp,
                            saddr.octets(),
                            self.ipv4_addr.octets(),
                        );
                        ip_header.write(&mut ip_packet);
                        ip_packet
                    }
                    _ => return Err(Box::new(Error::UnsupportedProtocol)),
                };
                let writer = self.tun.unwrap().writer();
                writer.write(ip_packet).await;
            }
        }
        Ok(())
    }

    async fn process_tcp_streams(&self, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        for (peer_id, peer) in self.peers {
            for ((saddr, sport), tcp_stream) in peer.tcp_streams {
                let (daddr, dport) = match tcp_stream.peer_addr()? {
                    SocketAddr::V4(socket) => (*socket.ip(), socket.port()),
                    _ => return Err(Box::new(Error::UnsupportedInternetProtocol)),
                };
                let mut payload = [0u8; MTU];
                tcp_stream.read(&mut payload).await;
                swarm.behaviour_mut().request_response.send_request(
                    peer_id,
                    Packet::In {
                        transport: Transport::Tcp {
                            saddr,
                            sport,
                            daddr,
                            dport,
                        },
                        payload,
                    },
                )
            }
        }
        Ok(())
    }

    async fn process_udp_streams(&self, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        for (peer_id, peer) in self.peers {
            for ((saddr, sport), udp_socket) in peer.udp_sockets {
                let (daddr, dport) = match udp_socket.peer_addr()? {
                    SocketAddr::V4(socket) => (*socket.ip(), socket.port()),
                    _ => return Err(Box::new(Error::UnsupportedInternetProtocol)),
                };
                let mut payload = [0u8; MTU];
                udp_socket.recv_from(&mut payload).await;
                swarm.behaviour_mut().request_response.send_request(
                    peer_id,
                    Packet::In {
                        transport: Transport::Udp {
                            saddr,
                            sport,
                            daddr,
                            dport,
                        },
                        payload,
                    },
                )
            }
        }
        Ok(())
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // create TUN device
        let tun = TunBuilder::new()
            .name("")
            .tap(false)
            .packet_info(false)
            .up()
            .mtu(MTU as i32)
            .try_build()
            .await?;

        // drop root privileges
        users::switch::set_effective_uid(self.user.uid())?;

        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen)?;

        // main loop
        let mut peer_packet = [0u8; MTU];
        let (mut tun_reader, mut tun_writer) = tun.split();
        loop {
            select! {
                packet = Packet::read_packet(&mut tun_reader) => {
                    let packet = packet?;
                    if let Some(peer) = self.get_peer(packet.daddr()) {
                        swarm.behaviour_mut().request_response.send_request(
                            &peer,
                            packet,
                        );
                    } else {
                        log::info!("no peer associated with addr")
                    }
                }
                e = swarm.select_next_some() => match e {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        self.process_peer_packet(&peer, &request).await?;
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

#[allow(dead_code)]
async fn race_udp_sockets() {
    // https://stackoverflow.com/questions/63715918/how-to-race-a-collection-of-futures-in-rust
    // https://stackoverflow.com/questions/72820408/how-to-get-the-result-of-the-first-future-to-complete-in-a-collection-of-futures
    // TODO benchmark futures::stream::FuturesUnordered vs futures::future::select_all
    use std::pin::Pin;
    type IoError = std::io::Error;
    type VecFuture = Vec<Pin<Box<dyn Future<Output = IoResult<PeerId>> + Send>>>;
    let udp_sockets = HashMap::new();
    udp_sockets.insert(
        PeerId::random(),
        (
            UdpSocket::bind("10.0.1.12:8080").await.unwrap(),
            [0u8; 1420],
        ),
    );
    let mut incoming_udp_tasks = udp_sockets.into_iter().map(|(peer_id, (socket, buf))| {
        socket
            .recv_from(&mut buf)
            .and_then(|nbytes| async move { Ok(peer_id) })
            .boxed()
    });
    let (output, index, remaining_tasks): (IoResult<PeerId>, usize, VecFuture) =
        select_all(incoming_udp_tasks).await;
    let peer_id: PeerId = output?;
    let (socket, buffer) = udp_sockets.get(&peer_id).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {}
}
