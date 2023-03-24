mod behaviour;
mod config;
mod request_response;

use async_std::fs::File;
use async_std::io::BufWriter;
use async_tun::Tun;
use behaviour::{Behaviour, Event};
use bimap::BiBTreeMap;
use cidr::Ipv4Cidr;
use clap::{Parser, Subcommand};
use config::Config;
use etherparse::InternetSlice;
use futures::io::AsyncWriteExt;
use libp2p::{
    development_transport,
    mdns::MdnsEvent,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use request_response::{PacketStreamCodec, PacketStreamProtocol};
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

pub(crate) const MTU: usize = 1420;
pub(crate) type Packet = [u8; MTU];
pub(crate) type PacketEvent = RequestResponseEvent<Packet, ()>;

pub struct PeerRoutingTable(BiBTreeMap<Ipv4Cidr, PeerId>);

#[derive(Debug)]
enum Error {
    PrivilegedUser,
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Error::PrivilegedUser => fmt.write_str("swarm should not be run as root"),
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
        #[clap(long, default_value = "/etc/p2p-tun/config.yaml")]
        config: String,
    },
    Run {
        #[clap(long, default_value = "/etc/p2p-tun/config.yaml")]
        config: String,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Opts::parse();
    match opts.command {
        CliCommand::Init { config } => {
            let cfg_path = PathBuf::from(config);
            let cfg = Config::default();
            std::fs::write(cfg_path, serde_yaml::to_string(&cfg)?)?;
        }
        CliCommand::Run { config } => {
            let cfg: Config = {
                let cfg_path = PathBuf::from(config);
                let cfg_str = std::fs::read_to_string(&cfg_path)?;
                let cfg = serde_yaml::from_str(&cfg_str)?;
                cfg
            };
            async_std::task::block_on(async move {
                log::debug!("creating tun device");
                // TODO make configurable
                let tun = async_tun::TunBuilder::new()
                    .name("")
                    .tap(false)
                    .mtu(MTU as i32)
                    .packet_info(false)
                    .up()
                    .try_build()
                    .await?;
                // TODO add ip addr to tun
                // TODO set netfilter to SNAT properly
                log::debug!("switching to user {}", cfg.user());
                drop_privileges(&cfg.user())?;
                log::debug!("starting swarm client");
                let swarm = {
                    let keypair = cfg.keypair()?;
                    let pub_key = keypair.public();
                    let peer_id = PeerId::from(pub_key.clone());
                    let transport = development_transport(keypair).await?;
                    let mut behaviour = Behaviour::new(peer_id, pub_key).await?;
                    for (peer_id, addr) in cfg.bootaddrs() {
                        behaviour.kademlia.add_address(&peer_id, addr.clone());
                    }
                    Swarm::new(transport, behaviour, peer_id)
                };
                start_client(tun, cfg.peer_routing_table()?, swarm, cfg.swarm_addr()).await
            })?;
        }
    }
    Ok(())
}

fn drop_privileges(username: &str) -> Result<()> {
    let uid = users::get_user_by_name(username)
        .expect("user to exist")
        .uid();
    let gid = users::get_group_by_name(username)
        .expect("group to exist")
        .gid();
    users::switch::set_both_gid(gid, gid)?;
    users::switch::set_both_uid(uid, uid)?;
    Ok(())
}

async fn start_client(
    tun: Tun,
    routing_table: PeerRoutingTable,
    mut swarm: Swarm<Behaviour>,
    swarm_addr: Multiaddr,
) -> Result<()> {
    // check that we are not privileged
    if users::get_current_uid() == 0
        || users::get_effective_gid() == 0
        || users::get_current_gid() == 0
        || users::get_effective_gid() == 0
    {
        return Err(Box::new(Error::PrivilegedUser));
    }

    let _listener_id = swarm.listen_on(swarm_addr)?;
    // TODO no need for this to be a contested resource
    let mut packet = [0u8; MTU];

    // main loop
    let mut tun_reader = tun.reader();
    let mut tun_writer = tun.writer();
    log::debug!("starting swarm");
    log::debug!("peer routing table:");
    for (cidr, peer_id) in &routing_table.0 {
        log::debug!("{cidr}: {peer_id}")
    }
    loop {
        use futures::{prelude::*, select};
        let mut tun_read_fut = tun_reader.read(&mut packet).fuse();
        select! {
            _ = tun_read_fut => {
                log::trace!("received packet on tun: {:?}", packet);
                handle_tun_packet(packet, &routing_table, &mut swarm);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                    peer,
                    message: RequestResponseMessage::Request { request, .. },
                })) => {
                    log::trace!("received packet from peer: {} - {:?}", peer.to_base58(), packet);
                    handle_peer_packet(request, &routing_table, &peer, &mut tun_writer).await?;
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

fn handle_tun_packet(
    packet: [u8; MTU],
    routing_table: &PeerRoutingTable,
    swarm: &mut Swarm<Behaviour>,
) {
    let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
        Ok(p) => p,
        Err(e) => {
            log::info!("could not parse packet received on TUN device: {e:?}");
            return;
        }
    };
    match sliced_packet.ip {
        Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
            let daddr = header_slice.destination_addr();
            log::debug!("packet is destined for {daddr}");
            for (cidr, peer_id) in &routing_table.0 {
                if cidr.contains(&daddr) {
                    log::debug!("associated peer: {peer_id}");
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, packet);
                    return;
                }
            }
            log::debug!("no peer corresponding to destination address")
        }
        _ => {
            log::trace!("unsupported packet type");
        }
    }
}

async fn handle_peer_packet(
    packet: [u8; MTU],
    routing_table: &PeerRoutingTable,
    peer_id: &PeerId,
    tun_writer: &mut BufWriter<&File>,
) -> std::io::Result<()> {
    let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
        Ok(p) => p,
        Err(_) => {
            log::info!("could not parse packet received from peer");
            return Ok(());
        }
    };
    match sliced_packet.ip {
        Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
            if let Some(cidr) = routing_table.0.get_by_right(peer_id) {
                let saddr = header_slice.source();
                if cidr.contains(&saddr.into()) {
                    tun_writer.write_all(&packet).await?;
                } else {
                    log::debug!(
                        "received packet outside of CIDR route from {}",
                        peer_id.to_base58()
                    );
                    log::debug!("expected {cidr}, got {saddr:?}");
                    log::debug!("dropping packet");
                }
            } else {
                log::debug!("received packet from unknown peer: {}", peer_id.to_base58());
            }
        }
        _ => {
            log::trace!("unsupported packet type");
        }
    }
    log::trace!("packet: {packet:?}");
    Ok(())
}
