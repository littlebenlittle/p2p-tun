mod packet;
mod request_response;

use async_std::{
    fs::File,
    io::{BufReader, BufWriter},
};
use async_tun::{Tun, TunBuilder};
use bimap::BiMap;
use clap::{Parser, Subcommand};
use futures::{prelude::*, select};
use libp2p::{
    development_transport,
    identity::Keypair,
    request_response::{
        ProtocolSupport, RequestResponse, RequestResponseEvent, RequestResponseMessage,
    },
    swarm::SwarmEvent,
    Multiaddr, NetworkBehaviour, PeerId, Swarm,
};
use log;
use serde::{Deserialize, Serialize};
use std::{error::Error, net::Ipv4Addr, path::PathBuf};

use packet::{Packet, PACKET_LEN};
use request_response::{PacketStreamCodec, PacketStreamProtocol};

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

#[derive(Serialize, Deserialize)]
struct Config {
    id_keys: Vec<u8>,
    peers: Vec<(String, String)>,
    listen: String,
}

impl Default for Config {
    fn default() -> Self {
        let id_keys = {
            let id_keys = libp2p::identity::ed25519::Keypair::generate();
            libp2p::identity::ed25519::Keypair::encode(&id_keys)
        };
        Self {
            id_keys: id_keys.to_vec(),
            peers: Vec::new(),
            listen: String::from("/ip4/0.0.0.0/tcp/0"),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let opts = Opts::parse();
    match opts.command {
        CliCommand::Init { out } => {
            let cfg_path = PathBuf::from(out);
            let cfg = Config::default();
            let cfg_str = serde_yaml::to_string(&cfg)?;
            std::fs::write(cfg_path, cfg_str)?;
        }
        CliCommand::Run { config } => {
            let mut cfg: Config = {
                let cfg_path = PathBuf::from(config);
                let cfg_str = std::fs::read_to_string(cfg_path)?;
                serde_yaml::from_str(&cfg_str)?
            };
            let id_keys = {
                let id_keys = libp2p::identity::ed25519::Keypair::decode(&mut cfg.id_keys[0..64])?;
                Keypair::Ed25519(id_keys)
            };
            let peers: BiMap<Ipv4Addr, PeerId> = {
                let mut peers: BiMap<Ipv4Addr, PeerId> = BiMap::new();
                for (ip4_addr, peer_id) in cfg.peers {
                    peers.insert(ip4_addr.parse()?, peer_id.parse()?);
                }
                peers
            };
            async_std::task::block_on(run(id_keys, cfg.listen.parse()?, peers))?;
        }
    }
    Ok(())
}

async fn run(
    id_keys: Keypair,
    listen_addr: Multiaddr,
    peers: BiMap<Ipv4Addr, PeerId>,
) -> Result<(), Box<dyn Error>> {
    // create the p2p swarm
    let mut swarm: Swarm<Behaviour> = {
        let peer_id = PeerId::from(id_keys.public());
        println!("peer id: {}", peer_id.to_base58());
        let transport = development_transport(id_keys).await?;
        let behaviour = Behaviour::default();
        Swarm::new(transport, behaviour, peer_id)
    };
    swarm.listen_on(listen_addr)?;

    // dial vpn peers
    for peer_id in peers.right_values() {
        swarm.dial(peer_id.clone())?;
    }

    // create TUN device
    let tun: Tun = match TunBuilder::new()
        .name("")
        .tap(false)
        .packet_info(false)
        .up()
        .mtu(PACKET_LEN as i32)
        .try_build()
        .await
    {
        Ok(tun) => tun,
        Err(e) => panic!("couldn't create tun device: {e:?}"),
    };
    let (mut tun_reader, mut tun_writer): (BufReader<&File>, BufWriter<&File>) = tun.split();

    // main loop
    let mut packet = [0u8; PACKET_LEN];
    loop {
        select! {
            result = tun_reader.read_exact(&mut packet).fuse() => {
                result?;
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                if let Some(peer_id) = peers.get_by_left(&dst) {
                    let peer_id: &PeerId = peer_id;
                    swarm.behaviour_mut().request_response.send_request(&peer_id, Packet(packet));
                } else {
                    log::info!("no registered peer for {dst:?}");
                }
            }
            e =  swarm.select_next_some() => match e {
                SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {peer, message})) => {
                    match message {
                        RequestResponseMessage::Request{request, ..} => {
                            if let Some(dst) = peers.get_by_right(&peer) {
                                let dst: &Ipv4Addr = dst;
                                let dst_bytes: [u8;4] = dst.octets();
                                let mut packet: [u8;1500] = request.0;
                                packet[16..20].copy_from_slice(&dst_bytes);
                                tun_writer.write(&packet).await?;
                            } else {
                                log::info!("no ip4 addr registered peer {peer:?}");
                            }
                        },
                        RequestResponseMessage::Response{..} => {},
                    }
                }
                SwarmEvent::Behaviour(_) => {}
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("now listening on {address:?}")
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("established connection to {}", peer_id.to_base58());
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    println!("closed connection to {}", peer_id.to_base58());
                }
                e => println!("{e:?}"),
            }
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
struct Behaviour {
    request_response: RequestResponse<PacketStreamCodec>,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            request_response: RequestResponse::new(
                PacketStreamCodec {},
                std::iter::once((PacketStreamProtocol {}, ProtocolSupport::Full)),
                Default::default(),
            ),
        }
    }
}

#[derive(Debug)]
enum Event {
    RequestResponse(RequestResponseEvent<Packet, ()>),
}

impl From<RequestResponseEvent<Packet, ()>> for Event {
    fn from(e: RequestResponseEvent<Packet, ()>) -> Self {
        Self::RequestResponse(e)
    }
}
