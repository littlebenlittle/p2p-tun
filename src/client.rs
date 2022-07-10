use crate::{
    Behaviour, Event, Ipv4Packet, PacketRequest, Port, Protocol::Tcp, Result, TcpPacket, MTU, Network
};
use cidr::Ipv4Cidr;
use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    str::FromStr,
    sync::{Mutex, MutexGuard},
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

//TODO handle for each error type
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
pub struct Client<'a, T: AsyncRead + AsyncWrite> {
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
    /// peers known to be associated with a given ipv4 forward addr
    cached_ipv4_peer: HashMap<Ipv4Addr, PeerId>,
    /// peers and daddrs we know we are acting as an exit for
    cached_should_exit: HashSet<(PeerId, Ipv4Addr)>,
    /// user that client will run as after creating
    /// network device file handles
    user: users::User,
    /// socket addresses associated with remote tcp service
    local_tcp_sockets: HashMap<(Ipv4Addr, Port), (Ipv4Addr, Port)>,
    tun: Mutex<T>,
    net: Mutex<Network<'a>>,
}

struct ClientBuilder<'a, T: AsyncRead + AsyncWrite> {
    keypair: Option<Keypair>,
    listen: Option<Multiaddr>,
    user: Option<String>,
    ipv4_addr: Option<Ipv4Addr>,
    tun: Option<T>,
    net: Option<Network<'a>>,
}

impl<'a, T: AsyncRead + AsyncWrite> ClientBuilder<'a, T> {
    /// set the keypair of p2p swarm peer
    pub fn keypair(self, keypair: Keypair) -> Self {
        Self {
            keypair: Some(keypair),
            listen: self.listen,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
            tun: self.tun,
            net: self.net,
        }
    }

    /// set the listen address of p2p swarm
    pub fn listen<M: Into<Multiaddr>>(self, listen: M) -> Self {
        Self {
            listen: Some(listen.into()),
            keypair: self.keypair,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
            tun: self.tun,
            net: self.net,
        }
    }

    /// set the user that p2p swarm will run as
    pub fn user(self, user: String) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: Some(user),
            ipv4_addr: self.ipv4_addr,
            tun: self.tun,
            net: self.net,
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
            tun: self.tun,
            net: self.net,
        }
    }

    pub fn tun(self, tun: T) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
            tun: Some(tun),
            net: self.net,
        }
    }

    pub fn net(self, net: Network<'a>) -> Self {
        Self {
            listen: self.listen,
            keypair: self.keypair,
            user: self.user,
            ipv4_addr: self.ipv4_addr,
            tun: self.tun,
            net: Some(net),
        }
    }
    pub fn build(self) -> Option<Client<'a, T>> {
        let keypair = self.keypair?;
        let net = self.net?;
        Some(Client {
            listen: self.listen?,
            network_ipv4_addr: *net.get_ipv4_addr(),
            peer_id: keypair.public().to_peer_id(),
            keypair,
            user: users::get_user_by_name(&self.user?)?,
            ipv4_addr: self.ipv4_addr?,
            peers: HashMap::new(),
            cached_ipv4_peer: HashMap::new(),
            cached_should_exit: HashSet::new(),
            local_tcp_sockets: HashMap::new(),
            tun: Mutex::new(self.tun?),
            net: Mutex::new(net),
        })
    }
}

impl<'a, T: AsyncRead + AsyncWrite + Unpin> Client<'a, T> {
    pub fn builder() -> ClientBuilder<'a, T> {
        ClientBuilder {
            keypair: None,
            listen: None,
            user: None,
            ipv4_addr: None,
            tun: None,
            net: None,
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
    fn get_ipv4_peer(&mut self, daddr: &Ipv4Addr) -> Result<&PeerId> {
        // check if we've cached this ip addr
        if let Some(peer_id) = self.cached_ipv4_peer.get(daddr) {
            return Ok(peer_id);
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
                return Ok(peer_id);
            }
        }
        return Err(Box::new(Error::NoMatchCidr));
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
    async fn handle_net_packet(&self, peer_id: &PeerId, mut packet: Vec<u8>) -> Result<()> {
        let mut ipv4_packet = Ipv4Packet::new(&mut packet)?;
        let daddr = ipv4_packet.destination_address();
        if !self.should_exit(&peer_id, &daddr) {
            return Err(Box::new(Error::NoMatchCidr));
        }
        let saddr = self.network_ipv4_addr;
        ipv4_packet.set_source_address(&saddr);
        match ipv4_packet.protocol()? {
            Tcp => {
                let mut tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                let dport = tcp_packet.destination_port();
                let peer = self.peers.get(&peer_id).unwrap();
                let sport = peer.get_exit_tcp_port(&daddr, &dport)?;
                tcp_packet.set_source_port(sport);
                tcp_packet.compute_checksum(&saddr, &daddr);
                send(&self.net, ipv4_packet.data()).await?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    /// handle a packet destined for the local TUN
    async fn handle_tun_packet(&mut self, peer_id: &PeerId, mut packet: Vec<u8>) -> Result<()> {
        let mut ipv4_packet = Ipv4Packet::new(&mut packet)?;
        // source address of the remote service
        let saddr = ipv4_packet.source_address();
        let daddr = match ipv4_packet.protocol()? {
            Tcp => {
                let mut tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                let dport = tcp_packet.destination_port();
                let peer = self.peers.get(&peer_id).unwrap();
                let sport = tcp_packet.source_port();
                let (daddr, dport) = self.get_local_tcp_socket(&saddr, &sport)?;
                tcp_packet.set_destination_port(dport);
                tcp_packet.compute_checksum(&saddr, &daddr);
                daddr
            }
            _ => unimplemented!(),
        };
        ipv4_packet.set_destination_address(daddr);
        send(&self.tun, ipv4_packet.data()).await?;
        Ok(())
    }

    /// process a packet received on TUN device
    fn process_tun_packet(&mut self, packet: Vec<u8>, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        let mut ipv4_packet = Ipv4Packet::new(&mut packet)?;
        let daddr = ipv4_packet.destination_address();
        let peer_id: &PeerId = self.get_ipv4_peer(&daddr)?;
        let saddr = ipv4_packet.source_address();
        match ipv4_packet.protocol()? {
            Tcp => {
                let tcp_packet = TcpPacket::new(&mut ipv4_packet.payload())?;
                let sport = tcp_packet.source_port();
                let dport = tcp_packet.destination_port();
                // TODO this runs for every packet; needs benchmark
                self.local_tcp_sockets
                    .insert((daddr, dport), (saddr, sport));
            }
            _ => unimplemented!(),
        }
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, PacketRequest::Remote(packet));
        Ok(())
    }

    /// process a packet received from the network
    fn process_net_packet(&mut self, packet: Vec<u8>, swarm: &mut Swarm<Behaviour>) -> Result<()> {
        let ipv4_packet = Ipv4Packet::new(&mut packet)?;
        let saddr = ipv4_packet.source_address();
        let peer_id = match ipv4_packet.protocol()? {
            Tcp => {
                let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                let sport = tcp_packet.source_port();
                let dport = tcp_packet.destination_port();
                self.get_source_peer(&saddr, &sport, &dport)?
            }
            _ => return Err(Box::new(Error::UnsupportedTransportProtocol)),
        };
        swarm
            .behaviour_mut()
            .request_response
            .send_request(peer_id, PacketRequest::Local(packet));
        Ok(())
    }

    /// get the source peer associated with given remote
    /// socket address and local destination port
    fn get_source_peer(
        &self,
        remote_addr: &Ipv4Addr,
        remote_sport: &Port,
        local_port: &Port,
    ) -> Result<&PeerId> {
        unimplemented!()
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // drop root privileges
        users::switch::set_effective_uid(self.user.uid())?;

        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen.clone())?;

        // main loop
        loop {
            use futures::{prelude::*, select};
            select! {
                packet = next(&self.tun) => self.process_tun_packet(packet?, &mut swarm)?,
                packet = next(&self.net) => self.process_net_packet(packet?, &mut swarm)?,
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        use PacketRequest::{Local, Remote};
                        match request {
                            Remote(packet) => self.handle_net_packet(&peer, packet).await?,
                            Local(packet) => self.handle_tun_packet(&peer, packet).await?,
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

async fn send<T: AsyncWrite + Unpin>(writer: &Mutex<T>, data: Vec<u8>) -> Result<()> {
    let mut writer: MutexGuard<T> = writer.lock().unwrap();
    match writer.write_all(&data).await {
        Ok(t) => Ok(t),
        Err(e) => Err(Box::new(e)),
    }
}

async fn next<T: AsyncRead + Unpin>(reader: &Mutex<T>) -> Result<Vec<u8>> {
    let mut reader: MutexGuard<T> = reader.lock().unwrap();
    let mut buf = [0u8; MTU];
    let nbytes = reader.read(&mut buf).await?;
    let mut data = Vec::<u8>::with_capacity(nbytes);
    data.copy_from_slice(&buf);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {}
}
