use crate::config::Config;
use crate::{Behaviour, Event, Result, MTU};
use crate::{config::VpnPeer};
use async_std::fs::File;
use async_tun::Tun;
use bimap::BiMap;
use cidr::Ipv4Cidr;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::RequestId;
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::fmt::Pointer;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    str::FromStr,
    sync::{Mutex, MutexGuard},
};

#[derive(Debug)]
pub enum Error {
    PrivilegedUser
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "swarm should not be run as root")
    }
}

impl std::error::Error for Error {}

//TODO check for conflicting forward CIDRs between peers
pub struct Client {
    peer_id: PeerId,
    keypair: Keypair,
    /// client's p2p swarm listen address
    listen: Multiaddr,
    peers: BiMap<PeerId, Ipv4Addr>,
    /// ip address of the tun device
    tun_ip4: Ipv4Addr,
    tun: Tun,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        Default::default()
    }

    /// Create p2p swarm and run client.
    pub async fn run(&mut self) -> Result<()> {
        // check that we are not privileged
        if users::get_current_uid() == 0 || users::get_effective_gid() == 0 || users::get_current_gid() == 0 || users::get_effective_gid() == 0 {
            return Err(Box::new(Error::PrivilegedUser))
        }
        
        // create swarm
        let mut swarm = make_swarm(&self.keypair).await?;
        let _listener_id = swarm.listen_on(self.listen.clone())?;

        let mut packet = [0u8; MTU];
        // main loop
        let mut tun_reader = self.tun.reader();
        let mut tun_writer = self.tun.writer();
        log::debug!("starting swarm");
        log::debug!("vpn peers:");
        for (peer_id, addr) in &self.peers {
            log::debug!("{peer_id}: {addr}")
        }
        loop {
            use futures::{prelude::*, select};
            let mut tun_read_fut = tun_reader.read(&mut packet).fuse();
            select! {
                _ = tun_read_fut => {
                    log::debug!("received packet on tun");
                    log::trace!("{:?}", packet);
                    use etherparse::InternetSlice;
                    let sliced_packet = etherparse::SlicedPacket::from_ip(&packet)?;
                    match sliced_packet.ip {
                        Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
                            let daddr= header_slice.destination_addr();
                            log::debug!("packet is destined for {daddr}");
                            if let Some(peer_id) = self.peers.get_by_right(&daddr) {
                                log::debug!("associated peer: {peer_id}");
                                swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_request(peer_id, packet.to_vec());
                            } else {
                                log::debug!("no peer corresponding to destination address")
                            }
                        },
                        _ => log::debug!("unsupported packet type")
                    }
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                        peer,
                        message: RequestResponseMessage::Request { request, .. },
                    })) => {
                        if let Some(saddr) = self.peers.get_by_left(&peer) {
                            log::debug!("received packet from {peer}");
                            let packet_saddr = etherparse::Ipv4HeaderSlice::from_slice(&packet)?.source_addr();
                            if *saddr != packet_saddr {
                                log::warn!("packet with different source addr received from {peer}: expected {saddr}, got {packet_saddr}");
                            }
                            tun_writer.write_all(&request).await?;
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

pub struct ClientBuilder {
    config: Option<Config>,
    tun: Option<Tun>,
}

impl ClientBuilder {
    pub fn build(self) -> Result<Client> {
        let cfg = self.config.ok_or("config not set")?;
        let mut peers = BiMap::new();
        for VpnPeer {ip, peer_id} in cfg.peers() {
            peers.insert(peer_id, ip);
        }
        Ok(Client {
            peer_id: cfg.peer_id(),
            keypair: cfg.keypair(),
            listen: cfg.listen(),
            tun_ip4: cfg.addr(),
            peers,
            tun: self.tun.ok_or("tun not set")?,
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

async fn make_swarm(id_keys: &Keypair) -> Result<Swarm<Behaviour>> {
    let pub_key = id_keys.public();
    let peer_id = PeerId::from(pub_key.clone());
    let transport = development_transport(id_keys.clone()).await?;
    let mut behaviour = Behaviour::new(peer_id, pub_key).await?;
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
