use crate::{Behaviour, Event, Ipv4Packet, Result, TcpPacket, MTU};
use cidr::Ipv4Cidr;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
use users::User;

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

impl<T> Into<Result<T>> for Error {
    fn into(self) -> Result<T> {
        return Err(Box::new(self));
    }
}

//TODO check for conflicting forward CIDRs between peers
pub struct Client<T: AsyncReaderWriter> {
    peer_id: PeerId,
    keypair: Keypair,
    /// client's p2p swarm listen address
    listen: Multiaddr,
    /// cidrs and peers that we will accept
    /// packets from
    accept: HashMap<PeerId, Vec<Ipv4Cidr>>,
    /// cidrs and peers that will we forward packets
    /// to
    /// TODO: check for conflicts
    forward: HashMap<PeerId, Vec<Ipv4Cidr>>,
    /// peers known to be associated with a given ipv4 forward addr
    cached_ipv4_peer: HashMap<Ipv4Addr, PeerId>,
    cached_should_accept: HashMap<(PeerId, Ipv4Addr), bool>,
    /// user that client will run as after creating
    /// network device file handles
    user: User,
    /// ip address of the tun device
    tun_ip4: Ipv4Addr,
    tun: T,
}

trait AsyncReaderWriter: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncReaderWriter> Client<T> {
    pub fn new(keypair: Keypair, listen: Multiaddr, user: User, tun: T) -> Client<T> {
        Client {
            peer_id: keypair.public().to_peer_id(),
            keypair,
            listen,
            user,
            accept: HashMap::new(),
            forward: HashMap::new(),
            cached_ipv4_peer: HashMap::new(),
            cached_should_accept: HashMap::new(),
            tun,
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
        for (peer_id, cidrs) in &mut self.forward {
            let mut found = false;
            for cidr in cidrs {
                if cidr.contains(daddr) {
                    self.cached_ipv4_peer.insert(*daddr, *peer_id);
                    return Ok(peer_id);
                }
            }
        }
        return Error::NoMatchCidr.into();
    }

    fn should_accept(&mut self, from: &PeerId, daddr: &Ipv4Addr) -> bool {
        match self.cached_should_accept.get(&(*from, *daddr)) {
            Some(b) => return *b,
            None => {}
        }
        for (peer_id, cidrs) in self.accept {
            if peer_id == *from {
                for cidr in cidrs {
                    if cidr.contains(&daddr) {
                        self.cached_should_accept.insert((peer_id, daddr), true);
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
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
                packet = next(&mut self.tun) => {
                    let packet = packet?;
                    let mut ipv4_packet = Ipv4Packet::new(&mut packet)?;
                    let daddr = ipv4_packet.destination_address();
                    let peer_id: &PeerId = self.get_ipv4_peer(&daddr)?;
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(peer_id, packet);
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        let packet = request;
                        match self.should_accept(&peer, packet) {
                            Ok(true) => self.tun.write_all(packet),
                            Ok(false) => log::info!("not accepting packet from {}", peer.to_base58()),
                            Err(e) => log::info!("not accepting packet from {}: {e}", peer.to_base58())
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

async fn send<T: AsyncWrite + Unpin>(writer: &mut T, data: Vec<u8>) -> Result<()> {
    match writer.write_all(&data).await {
        Ok(t) => Ok(t),
        Err(e) => Err(Box::new(e)),
    }
}

async fn next<T: AsyncRead + Unpin>(reader: &mut T) -> Result<Vec<u8>> {
    let mut buf = [0u8; MTU];
    let nbytes = reader.read(&mut buf).await?;
    let mut data = Vec::<u8>::with_capacity(nbytes);
    data.copy_from_slice(&buf);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Network, Tun};

    #[test]
    fn test() {
        let tun_a = Vec::<u8>::new();
        let tun_b = Vec::<u8>::new();
        let net_a = Vec::<u8>::new();
        let net_b = Vec::<u8>::new();
        // create a fake IP packet
        let mut packet = vec![
            0x45, // version 4, IHL 5 (IHL doesn't matter right now, but it will)
            0,    // DSCP and ECN don't matter
            0, 0, // total length doesn't matter
            0, 0, 0, 0, // identifiaction, flags, fragment offset don't matter
            0, // ttl doesn't matter
            6, // protocol is TCP
            0, 0, // we compute checksum later
            192, 168, 0, 1, // source address
            127, 0, 0, 1, // destination address
            771, 9, // TCP source port 12345
            500, 5, // TCP dest port 8080
            0, 0, 0, 0, // seq number, doesn't matter
            0, 0, 0, 0, // ack number, doesn't matter
            0, 0, 0, 0, // other TCP headers, don't matter
            0, 0, // compute TCP checksum later
            0, 0, // urgent pointer, doesn't matter
            1, 2, 3, 4, 5, // TCP payload
        ];
        let mut ipv4_packet = Ipv4Packet::new(&mut packet).unwrap();
        ipv4_packet.compute_checksum();
    }
}
