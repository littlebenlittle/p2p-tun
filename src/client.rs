use crate::config::Config;
use crate::config::VpnPeer;
use crate::{Behaviour, Event, Result, MTU};
use async_std::fs::File;
use async_std::io::BufWriter;
use async_tun::Tun;
use bimap::BiMap;
use cidr::Ipv4Cidr;
use etherparse::InternetSlice;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::core::network::Peer;
use libp2p::request_response::RequestId;
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    mdns::MdnsEvent,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

#[derive(Debug)]
pub enum Error {
    PrivilegedUser,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "swarm should not be run as root")
    }
}

impl std::error::Error for Error {}

type ShouldForward = bool;

//TODO check for conflicting forward CIDRs between peers
pub struct Client {
    /// client's p2p swarm listen address
    listen: Multiaddr,
    peers: BiMap<PeerId, Ipv4Addr>,
    /// ip address of the tun device
    tun: Option<Tun>,
    swarm: Swarm<Behaviour>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        Default::default()
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // check that we are not privileged
        if users::get_current_uid() == 0
            || users::get_effective_gid() == 0
            || users::get_current_gid() == 0
            || users::get_effective_gid() == 0
        {
            return Err(Box::new(Error::PrivilegedUser));
        }

        let _listener_id = self.swarm.listen_on(self.listen.clone())?;
        // TODO no need for this to be a contested resource
        let mut packet = [0u8; MTU];

        // main loop
        let tun = self.tun.take().expect("tun should not be None");
        let mut tun_reader = tun.reader();
        let mut tun_writer = tun.writer();
        log::debug!("starting swarm");
        log::debug!("vpn peers:");
        for (peer_id, addr) in &self.peers {
            log::debug!("{addr}: {peer_id}")
        }
        loop {
            use futures::{prelude::*, select};
            let mut tun_read_fut = tun_reader.read(&mut packet).fuse();
            select! {
                _ = tun_read_fut => {
                    log::trace!("{:?}", packet);
                    self.handle_tun_packet(packet);
                }
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        packet.copy_from_slice(&request[0..MTU]);
                        self.handle_peer_packet(peer, packet, &mut tun_writer).await?;
                    }
                    SwarmEvent::Behaviour(Event::Mdns(MdnsEvent::Discovered(addresses))) => {
                        for (peer_id, _) in addresses {
                            log::debug!("new peer connection: {}", peer_id.to_base58())
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

    fn handle_tun_packet(&mut self, packet: [u8; MTU]) {
        let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
            Ok(p) => p,
            Err(e) => {
                log::info!("could not parse packet received on TUN device");
                return;
            }
        };
        match sliced_packet.ip {
            Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
                let daddr = header_slice.destination_addr();
                log::debug!("packet is destined for {daddr}");
                if let Some(peer_id) = self.peers.get_by_right(&daddr) {
                    log::debug!("associated peer: {peer_id}");
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(peer_id, packet.to_vec());
                } else {
                    log::debug!("no peer corresponding to destination address")
                }
            }
            _ => {
                log::trace!("unsupported packet type");
            }
        }
    }

    async fn handle_peer_packet(
        &mut self,
        peer: PeerId,
        packet: [u8; MTU],
        tun_writer: &mut BufWriter<&File>,
    ) -> std::io::Result<()> {
        if let Some(saddr) = self.peers.get_by_left(&peer) {
            let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
                Ok(p) => p,
                Err(e) => {
                    log::info!("could not parse packet received on from peer");
                    return Ok(());
                }
            };
            match sliced_packet.ip {
                Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
                    let packet_saddr = header_slice.source_addr();
                    if packet_saddr != *saddr {
                        log::warn!("packet with different source addr received from {peer}: expected {saddr}, got {packet_saddr}");
                    }
                    tun_writer.write_all(&packet).await?;
                }
                _ => {
                    log::trace!("unsupported packet type");
                }
            }
        }
        Ok(())
    }
}

pub struct ClientBuilder {
    config: Option<Config>,
    tun: Option<Tun>,
}

impl ClientBuilder {
    pub async fn build(self) -> Result<Client> {
        let cfg = self.config.ok_or("config not set")?;
        let mut peers = BiMap::new();
        for VpnPeer { ip, peer_id } in cfg.peers() {
            peers.insert(peer_id, ip);
        }
        Ok(Client {
            listen: cfg.listen(),
            peers,
            tun: Some(self.tun.ok_or("tun not set")?),
            swarm: {
                let pub_key = cfg.keypair().public();
                let peer_id = PeerId::from(pub_key.clone());
                let transport = development_transport(cfg.keypair()).await?;
                let mut behaviour = Behaviour::new(peer_id, pub_key).await?;
                for (peer_id, addr) in cfg.bootaddrs() {
                    behaviour.kademlia.add_address(&peer_id, addr.clone());
                }
                Swarm::new(transport, behaviour, peer_id)
            },
        })
    }

    pub fn config(self, config: Config) -> Self {
        Self {
            config: Some(config),
            tun: self.tun,
        }
    }

    pub fn tun(self, tun: Tun) -> Self {
        Self {
            config: self.config,
            tun: Some(tun),
        }
    }

}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            config: None,
            tun: None,
        }
    }
}
