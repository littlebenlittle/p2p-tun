use crate::Result;
use futures::prelude::*;
use std::{io, net::Ipv4Addr};

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

// TODO actually calculate this
/// maxiumum allowed payload length given the length of serialized headers
pub const MTU: usize = 1420;

pub type Port = u16;

#[derive(PartialEq)]
pub struct Packet {
    transport: Transport,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
}

impl Packet {
    pub fn from_ip(packet: &[u8]) -> io::Result<Self> {
        let sliced_packet = match SlicedPacket::from_ip(&packet) {
            Ok(packet) => packet,
            Err(e) => return Err(io::ErrorKind::InvalidData.into()),
        };
        let (saddr, daddr) = match sliced_packet.ip {
            Some(InternetSlice::Ipv4(header, extensions)) => {
                (header.source_addr(), header.destination_addr())
            }
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let mut payload = Vec::<u8>::with_capacity(sliced_packet.payload.len());
        payload.copy_from_slice(sliced_packet.payload);
        let transport = match sliced_packet.transport {
            Some(TransportSlice::Tcp(headers)) => Transport::Tcp {
                sport: headers.source_port(),
                dport: headers.destination_port(),
                payload,
            },
            Some(TransportSlice::Udp(headers)) => Transport::Udp {
                sport: headers.source_port(),
                dport: headers.destination_port(),
                payload,
            },
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        Ok(Self {
            transport,
            saddr,
            daddr,
        })
    }

    pub fn to_wire_format(&self) -> Vec<u8> {
        let transport_data = self.transport().to_wire_format();
        let mut data = Vec::<u8>::with_capacity(
            4 + // saddr octets
            4 + // daddr octets
            transport_data.len(),
        );
        // copy src address
        data[0..4].copy_from_slice(&self.saddr().octets());
        // copy dst address
        data[4..8].copy_from_slice(&self.daddr().octets());
        // copy transport headers
        data[8..transport_data.len()].copy_from_slice(&transport_data);
        // copy payload
        data[8 + transport_data.len()..].copy_from_slice(&self.transport.payload());
        data
    }

    pub fn from_wire_format(data: &[u8]) -> io::Result<Self> {
        let saddr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let daddr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let transport = Transport::from_wire_format(&data[8..])?;
        Ok(Self {
            saddr,
            daddr,
            transport,
        })
    }

    pub fn len(&self) -> usize {
        unimplemented!()
    }

    pub async fn read_packet<T: AsyncRead + Unpin>(reader: &mut T) -> Result<Packet> {
        let mut buf = [0u8; MTU];
        let nbytes: usize = reader.read(&mut buf).await?;
        match Packet::from_ip(&buf[..nbytes]) {
            Ok(packet) => Ok(packet),
            Err(e) => Err(Box::new(e)),
        }
    }

    pub fn saddr(&self) -> &Ipv4Addr {
        &self.saddr
    }

    pub fn daddr(&self) -> &Ipv4Addr {
        &self.daddr
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }
}

#[derive(PartialEq)]
enum Transport {
    Tcp {
        sport: Port,
        dport: Port,
        payload: Vec<u8>,
    },
    Udp {
        sport: Port,
        dport: Port,
        payload: Vec<u8>,
    },
}

impl Transport {
    fn to_wire_format(&self) -> Vec<u8> {
        match self {
            Self::Tcp {
                sport,
                dport,
                payload,
            } => {
                let mut data = Vec::<u8>::with_capacity(5 + payload.len());
                data[0] = 0;
                data[1] = ((sport >> 8) & 0xff) as u8;
                data[2] = (sport & 0xff) as u8;
                data[3] = ((dport >> 8) & 0xff) as u8;
                data[4] = (dport & 0xff) as u8;
                data[5..].copy_from_slice(&payload);
                data
            }
            Self::Udp {
                sport,
                dport,
                payload,
            } => {
                let mut data = Vec::<u8>::with_capacity(5 + payload.len());
                data[0] = 1;
                data[1] = ((sport >> 8) & 0xff) as u8;
                data[2] = (sport & 0xff) as u8;
                data[3] = ((dport >> 8) & 0xff) as u8;
                data[4] = (dport & 0xff) as u8;
                data[5..].copy_from_slice(&payload);
                data
            }
        }
    }

    fn from_wire_format(data: &[u8]) -> io::Result<Self> {
        match data[0] {
            0 => {
                let payload = Vec::<u8>::with_capacity(data.len() - 4);
                payload.copy_from_slice(&data[5..]);
                Ok(Self::Tcp {
                    sport: ((data[1] << 8) | data[2]) as u16,
                    dport: ((data[3] << 8) | data[4]) as u16,
                    payload,
                })
            }
            0 => {
                let payload = Vec::<u8>::with_capacity(data.len() - 4);
                payload.copy_from_slice(&data[5..]);
                Ok(Self::Udp {
                    sport: ((data[1] << 8) | data[2]) as u16,
                    dport: ((data[3] << 8) | data[4]) as u16,
                    payload,
                })
            }
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Tcp { payload, .. } | Self::Udp { payload, .. } => payload,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidIpHeaders,
    UnsupportedInternetProtocol,
    InvalidTransportHeaders,
    UnsupportedTransportProtocol,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidIpHeaders => fmt.write_str("invalid ip headers"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn transport_wire_format_encode_decode() {
        for sport in 0..0xff {
            for dport in 0..0xff {
                let payload = vec![1, 2, 3];
                let tcp = Transport::Tcp {
                    sport,
                    dport,
                    payload,
                };
                let udp = Transport::Udp {
                    sport,
                    dport,
                    payload,
                };
                assert_eq!(tcp, Transport::from_wire_format(&tcp.to_wire_format()));
                assert_eq!(udp, Transport::from_wire_format(&udp.to_wire_format()));
            }
        }
    }
}

// TODO: add req/res to change MTU
// Pub const PACKET_LEN: usize = 1500;
//
// #[derive(Debug, Clone)]
// Pub struct Packet(pub [u8; PACKET_LEN]);
//
// Impl From<Packet> for Vec<u8> {
//     fn from(packet: Packet) -> Vec<u8> {
//         packet.0.into()
//     }
// }
//
// #[derive(Debug)]
// Pub enum Error {
//     Overflow,
// }
//
// Impl std::fmt::Display for Error {
//     fn fmt(&self, formatter: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
//         match self {
//             Error::Overflow => formatter.write_str("packet overflow"),
//         }
//     }
// }
//
// Impl std::error::Error for Error {}
//
// Impl From<Error> for std::io::Error {
//     fn from(e: Error) -> std::io::Error {
//         std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}"))
//     }
// }
//
// Impl TryInto<Packet> for Vec<u8> {
//     type Error = Error;
//     fn try_into(self) -> Result<Packet, Self::Error> {
//         if self.len() > PACKET_LEN {
//             return Err(Error::Overflow);
//         }
//         let mut packet = [0u8; PACKET_LEN];
//         packet[..self.len()].copy_from_slice(&self[..]);
//         Ok(Packet(packet))
//     }
// }
