mod behaviour;
mod config;
mod packet;
mod request_response;

use async_tun::{Tun, TunBuilder};
use bimap::BiMap;
use clap::{Parser, Subcommand};
use futures::{prelude::*, select};
use libp2p::{
    development_transport,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use log;
use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

use behaviour::{Behaviour, Event};
use config::Config;
use packet::{Packet, PACKET_LEN};
use request_response::{PacketStreamCodec, PacketStreamProtocol};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

#[derive(Debug)]
enum Error {
    NoPeers,
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Error::NoPeers => fmt.write_str("no vpn peers specified in config"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    Init {
        #[clap(long)]
        out: String,
    },
    Run {
        #[clap(long)]
        config: String,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Opts::parse();
    match opts.command {
        CliCommand::Init { out } => {
            let cfg_path = PathBuf::from(out);
            let cfg = Config::default();
            std::fs::write(cfg_path, serde_yaml::to_string(&cfg)?)?;
        }
        CliCommand::Run { config } => {
            log::info!("running p2p-tun");
            let mut cfg: Config = {
                let cfg_path = PathBuf::from(config);
                let cfg_str = std::fs::read_to_string(&cfg_path)?;
                let cfg = serde_yaml::from_str(&cfg_str)?;
                log::info!("loaded config from: {:?}", cfg_path);
                cfg
            };
            let id_keys = cfg.private_key()?;
            let peers: BiMap<Ipv4Addr, PeerId> = {
                if cfg.peers().is_empty() {
                    return Err(Box::new(Error::NoPeers));
                }
                let mut peers: BiMap<Ipv4Addr, PeerId> = BiMap::new();
                for peer in cfg.peers() {
                    peers.insert(peer.ip, peer.peer_id);
                }
                peers
            };
            let user = users::get_user_by_name(cfg.user()).expect("user does not exist");

            async_std::task::block_on(async {
                // create TUN device
                let tun: Tun = create_tun().await?;
                log::info!("created tun device: {}", tun.name());
                // drop root
                users::switch::set_effective_uid(user.uid())?;
                run(id_keys, cfg.listen(), peers, tun).await
            })?;
        }
    }
    Ok(())
}

async fn run(
    id_keys: Keypair,
    listen_addr: Multiaddr,
    peers: BiMap<Ipv4Addr, PeerId>,
    tun: Tun,
) -> Result<()> {
    // insecure to be root
    assert_ne!(users::get_effective_uid(), 0);

    // create the p2p swarm
    let mut swarm: Swarm<Behaviour> = {
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
        Swarm::new(transport, behaviour, peer_id)
    };

    // start node
    swarm.listen_on(listen_addr.clone())?;
    log::info!("swarm listening on: {}", listen_addr);

    // main loop
    let mut packet = [0u8; PACKET_LEN];
    let (mut tun_reader, mut tun_writer) = tun.split();
    loop {
        select! {
            result = tun_reader.read(&mut packet).fuse() => {
                result?;
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                if let Some(peer_id) = peers.get_by_left(&dst) {
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
                    if let Some(src) = peers.get_by_right(&peer) {
                        let src_bytes: [u8; 4] = src.octets();
                        let mut packet: [u8; 1500] = request.0;
                        packet[12..16].copy_from_slice(&src_bytes);
                        tun_writer.write(&packet).await?;
                    } else {
                        log::info!("no ip4 addr registered peer {}", peer.to_base58());
                    }
                }
                SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received{ peer_id, info })) => {
                    let info: IdentifyInfo = info;
                    let peer_id: PeerId = peer_id;
                    log::info!("peer info received for {}", peer_id.to_base58());
                    if peers.contains_right(&peer_id) {
                        log::info!("adding peer addresses");
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

async fn create_tun() -> Result<Tun> {
    // must be root
    assert_eq!(users::get_current_uid(), 0);
    TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .up()
        .mtu(PACKET_LEN as i32)
        .try_build()
        .await
}
