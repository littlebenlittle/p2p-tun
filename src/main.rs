use async_std::{
    fs::File,
    io::{self, BufReader, BufWriter},
};
use async_trait::async_trait;
use async_tun::{Tun, TunBuilder};
use bimap::BiMap;
use clap::{Parser, Subcommand};
use futures::{prelude::*, select};
use libp2p::core::upgrade::{
    read_length_prefixed, write_length_prefixed, ProtocolName,
};
use libp2p::development_transport;
use libp2p::identity::Keypair;
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaConfig, KademliaEvent};
use libp2p::request_response::{
    ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseEvent,
    RequestResponseMessage,
};
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::{NetworkBehaviour, Swarm};
use log;
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, error::Error, net::Ipv4Addr, path::PathBuf, str::FromStr};

const PACKET_LEN: usize = 1500;

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
        let mut behaviour = Behaviour::new(peer_id.clone());
        let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
        for peer in [
            "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        ] {
            let id = PeerId::from_str(peer)?;
            behaviour.kademlia.add_address(&id, bootaddr.clone());
        }
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
    kademlia: Kademlia<MemoryStore>,
    request_response: RequestResponse<PacketStreamCodec>,
}

impl Behaviour {
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            kademlia: Kademlia::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                KademliaConfig::default(),
            ),
            request_response: RequestResponse::new(
                PacketStreamCodec(),
                std::iter::once((PacketStreamProtocol(), ProtocolSupport::Full)),
                Default::default(),
            ),
        }
    }
}

#[derive(Debug)]
enum Event {
    Kademlia(KademliaEvent),
    RequestResponse(RequestResponseEvent<Packet, ()>),
}

impl From<KademliaEvent> for Event {
    fn from(e: KademliaEvent) -> Self {
        Self::Kademlia(e)
    }
}

impl From<RequestResponseEvent<Packet, ()>> for Event {
    fn from(e: RequestResponseEvent<Packet, ()>) -> Self {
        Self::RequestResponse(e)
    }
}

#[derive(Clone, Default)]
struct PacketStreamProtocol();

impl ProtocolName for PacketStreamProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/packet-stream-1500/1".as_bytes()
    }
}

#[derive(Debug, Clone)]
struct PacketStreamCodec();

#[derive(Debug)]
struct Packet([u8; PACKET_LEN]);

#[derive(Debug)]
enum PacketError {
    Overflow,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            PacketError::Overflow => formatter.write_str("packet overflow"),
        }
    }
}

impl std::error::Error for PacketError {}

impl From<PacketError> for std::io::Error {
    fn from(e: PacketError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}"))
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        packet.0.into()
    }
}

impl TryInto<Packet> for Vec<u8> {
    type Error = PacketError;
    fn try_into(self) -> Result<Packet, Self::Error> {
        if self.len() > PACKET_LEN {
            return Err(PacketError::Overflow);
        }
        let mut packet = [0u8; PACKET_LEN];
        packet[..self.len()].copy_from_slice(&self[..]);
        Ok(Packet(packet))
    }
}

#[async_trait]
impl RequestResponseCodec for PacketStreamCodec {
    type Protocol = PacketStreamProtocol;
    type Request = Packet;
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _: &PacketStreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, PACKET_LEN).await?;
        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let packet: Packet = vec.try_into()?;
        Ok(packet)
    }

    async fn read_response<T>(
        &mut self,
        _: &PacketStreamProtocol,
        _: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        Ok(())
    }

    async fn write_request<T>(
        &mut self,
        _: &PacketStreamProtocol,
        io: &mut T,
        packet: Packet,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let vec: Vec<u8> = packet.into();
        write_length_prefixed(io, vec).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &PacketStreamProtocol,
        _: &mut T,
        _: (),
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Ok(())
    }
}
