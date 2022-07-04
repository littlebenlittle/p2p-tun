mod behaviour;
mod client;
mod config;
mod packet;
mod request_response;

use behaviour::{Behaviour, Event};
use client::Client;
use config::Config;
use packet::{Packet, MTU, Port};
use request_response::{PacketStreamCodec, PacketStreamProtocol};

use bimap::BiMap;
use clap::{Parser, Subcommand};
use libp2p::PeerId;
use log;
use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

pub(crate) const MTU_SIZE: usize = 1500;

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
            let mut cfg: Config = {
                let cfg_path = PathBuf::from(config);
                let cfg_str = std::fs::read_to_string(&cfg_path)?;
                let cfg = serde_yaml::from_str(&cfg_str)?;
                cfg
            };
            let keypair = cfg.keypair();
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
            async_std::task::block_on(async {
                let mut client = Client::builder()
                    .keypair(cfg.keypair())
                    .listen(cfg.listen())
                    .build()
                    .unwrap();
                client.run().await
            })?;
        }
    }
    Ok(())
}
