mod behaviour;
mod config;
mod request_response;

use async_std::{
    fs::File,
    io::{stdin, BufWriter},
};
use async_tun::Tun;
use behaviour::{Behaviour, Event};
use bimap::BiBTreeMap;
use cidr::Ipv4Cidr;
use clap::{Parser, Subcommand};
use config::Config;
use etherparse::InternetSlice;
use futures::{io::AsyncWriteExt, prelude::*, select};
use libp2p::{
    development_transport,
    mdns::MdnsEvent,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use request_response::{PacketStreamCodec, PacketStreamProtocol};
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

pub(crate) const MTU: usize = 1420;
pub(crate) type Packet = [u8; MTU];
pub(crate) type PacketEvent = RequestResponseEvent<Packet, ()>;

pub struct PeerRoutingTable(BiBTreeMap<Ipv4Cidr, PeerId>);

#[derive(Parser)]
struct Opts {
    #[clap(long, default_value = "./config.yaml")]
    config: String,
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    Init,
    Run,
    /// Create tun and dump packets for debugging instead of forwarding to peer
    Dump,
    /// Create tun and write fake packets to it for debug
    Fake,
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Opts::parse();
    use CliCommand::*;
    match opts.command {
        Init => {
            let cfg = Config::default();
            let cfg_path = PathBuf::from(opts.config);
            if cfg_path.exists() {
                println!("config path already exists; not overwriting")
            } else {
                std::fs::write(cfg_path, serde_yaml::to_string(&cfg)?)?;
            }
        }
        Run => async_std::task::block_on(run(Config::from_path(opts.config)?))?,
        Dump => async_std::task::block_on(dump(Config::from_path(opts.config)?))?,
        Fake => async_std::task::block_on(fake(Config::from_path(opts.config)?))?,
    }
    Ok(())
}

async fn run(cfg: Config) -> Result<()> {
    log::debug!("creating tun device");
    let tun = setup_tun(&cfg).await?;
    log::debug!("switching to user {}", cfg.user());
    drop_privileges(&cfg.user())?;
    log::debug!("starting swarm client");
    let swarm_addr = cfg.swarm_addr();
    let routing_table = cfg.peer_routing_table()?;
    let mut swarm = {
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
    let _listener_id = swarm.listen_on(swarm_addr)?;
    // TODO no need for this to be a contested resource
    let mut packet = [0u8; MTU];

    // main loop
    let (mut tun_reader, mut tun_writer) = tun.split();
    log::debug!("starting swarm");
    log::debug!("peer routing table:");
    for (cidr, peer_id) in &routing_table.0 {
        log::debug!("{cidr}: {peer_id}")
    }
    loop {
        log::debug!("main loop");
        select! {
            _ = tun_reader.read(&mut packet).fuse() => {
                if let Some(peer_id) = handle_tun_packet(packet, &routing_table) {
                    log::debug!("sending packet to peer");
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, packet);
                    log::debug!("finished sending packet to peer");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(Event::RequestResponse(RequestResponseEvent::Message {
                    peer,
                    message: RequestResponseMessage::Request { request, .. },
                })) => {
                    if handle_peer_packet(request, &routing_table, &peer).await? {
                        log::debug!("writing packet to tun device");
                        let n = tun_writer.write(&request).await?;
                        log::debug!("wrote {n} bytes");
                        log::debug!("flushing writer");
                        tun_writer.flush().await?;
                        log::debug!("finished writing packet to tun device");
                   }
                }
                // SwarmEvent::Behaviour(Event::Mdns(MdnsEvent::Discovered(addresses))) => {
                //     for (peer_id, _) in addresses {
                //         log::debug!("new peer connection: {}", peer_id.to_base58())
                //     }
                // }
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

async fn dump(cfg: Config) -> Result<()> {
    log::info!("creating tun device");
    let tun = setup_tun(&cfg).await?;
    log::info!("switching to user {}", cfg.user());
    drop_privileges(&cfg.user())?;
    let mut tun_reader = tun.reader();
    let mut packet = [0u8; MTU];
    let routing_table = cfg.peer_routing_table()?;
    loop {
        let mut tun_read_fut = tun_reader.read(&mut packet).fuse();
        select! {
            _ = tun_read_fut => {
                handle_tun_packet(packet, &routing_table);
            }
        }
    }
    Result::<()>::Ok(())
}

async fn fake(cfg: Config) -> Result<()> {
    log::info!("creating tun device");
    let tun = setup_tun(&cfg).await?;
    log::info!("switching to user {}", cfg.user());
    drop_privileges(&cfg.user())?;
    let mut tun_writer = tun.writer();
    let mut counter = 0u8;
    let stdin = async_std::io::stdin();
    let mut line = String::new();
    loop {
        let packet_builder =
            etherparse::PacketBuilder::ipv4([1, 2, 3, 4], [4, 3, 2, 1], 30).udp(1234, 4321);
        let payload = [counter];
        let mut packet = Vec::with_capacity(packet_builder.size(1));
        packet_builder.write(&mut packet, &payload)?;
        log::debug!("writing packet to {}", tun.name());
        tun_writer.write(&packet).await?;
        tun_writer.flush().await?;
        log::debug!("finished writing packet to {}", tun.name());
        stdin.read_line(&mut line).await?;
        counter += 1;
    }
    Result::<()>::Ok(())
}

async fn setup_tun(cfg: &Config) -> Result<Tun> {
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
    Ok(tun)
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

fn handle_tun_packet(packet: [u8; MTU], routing_table: &PeerRoutingTable) -> Option<&PeerId> {
    log::debug!("received packet on tun");
    let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
        Ok(p) => p,
        Err(e) => {
            log::info!("could not parse packet received on TUN device: {e:?}");
            return None;
        }
    };
    match sliced_packet.ip {
        Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
            let daddr = header_slice.destination_addr();
            log::debug!("packet is destined for {daddr}");
            for (cidr, peer_id) in &routing_table.0 {
                if cidr.contains(&daddr) {
                    log::debug!("associated peer: {peer_id}");
                    return Some(peer_id);
                } else {
                    log::debug!("no peer route associated with destination");
                }
            }
            log::debug!("no peer corresponding to destination address")
        }
        _ => {
            log::trace!("unsupported packet type");
        }
    }
    None
}

async fn handle_peer_packet(
    packet: [u8; MTU],
    routing_table: &PeerRoutingTable,
    peer_id: &PeerId,
) -> std::io::Result<bool> {
    log::debug!("received packet from peer");
    log::trace!("packet: {:?}", packet);
    let sliced_packet = match etherparse::SlicedPacket::from_ip(&packet) {
        Ok(p) => p,
        Err(_) => {
            log::info!("could not parse packet received from peer");
            return Ok(false);
        }
    };
    match sliced_packet.ip {
        Some(InternetSlice::Ipv4(header_slice, _extensions_slice)) => {
            if let Some(cidr) = routing_table.0.get_by_right(peer_id) {
                let saddr = header_slice.source();
                log::debug!("src: {saddr:?}, dst: {:?}", header_slice.destination());
                if cidr.contains(&saddr.into()) {
                    return Ok(true);
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
    Ok(false)
}
