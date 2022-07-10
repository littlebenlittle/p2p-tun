use crate::Result;
use futures::prelude::*;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

// TODO actually calculate this
/// maxiumum allowed payload length given the length of
/// transmitted packet headers
pub const MTU: usize = 1420;

pub type Port = u16;

#[derive(Debug)]
pub struct Ipv4Packet<'a>(&'a mut [u8]);

impl<'a> Ipv4Packet<'a> {
    pub fn new(data: &'a mut [u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Box::new(Error::InvalidIpHeaders))
        }
        Ok(Self(data))
    }

    pub fn data(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn protocol(&self) -> Result<Protocol> {
        match &self.0[9] {
            0x01 => Ok(Protocol::Icmp),
            0x06 => Ok(Protocol::Tcp),
            0x11 => Ok(Protocol::Udp),
            _ => Err(Box::new(Error::UnsupportedTransportProtocol)),
        }
    }

    pub fn source_address(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[12], self.0[13], self.0[14], self.0[15])
    }

    pub fn destination_address(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[16], self.0[17], self.0[18], self.0[19])
    }

    pub fn set_source_address(&mut self, addr: &Ipv4Addr) {
        let octets = addr.octets();
        for i in 0..4 {
            self.0[12 + i] = octets[i];
        }
    }

    pub fn set_destination_address(&mut self, addr: &Ipv4Addr) {
        let octets = addr.octets();
        for i in 0..4 {
            self.0[16 + i] = octets[i];
        }
    }

    pub fn compute_checksum(&mut self) {
        let sum: u8 = self.0[0..5].iter().chain(self.0[6..9].iter()).sum();
        self.0[5] = sum ^ 0o1;
    }

    pub fn payload(&self) -> &mut [u8] {
        &mut self.0[20..]
    }
}

pub struct TcpPacket<'a>(&'a mut [u8]);

impl<'a> TcpPacket<'a> {
    pub fn new(data: &'a mut [u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Box::new(Error::InvalidTransportHeaders))
        }
        Ok(Self(data))
    }

    pub fn source_port(&self) -> Port {
        (self.0[0] << 8) as u16 | self.0[1] as u16
    }

    pub fn destination_port(&self) -> Port {
        (self.0[2] << 8) as u16 | self.0[3] as u16
    }

    pub fn set_source_port(&self, port: &Port) {
        let port_bytes = port.to_be_bytes();
        self.0[0] = port_bytes[0];
        self.0[1] = port_bytes[1];
    }

    pub fn set_destination_port(&self, port: &Port) {
        let port_bytes = port.to_be_bytes();
        self.0[2] = port_bytes[0];
        self.0[3] = port_bytes[1];
    }

    pub fn compute_checksum(&mut self, src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr) {
        // pseudo header
        let src_octets = src_addr.octets();
        let dst_octets = dst_addr.octets();
        let mut ph = [0u8; 12];
        for i in 0..4 {
            ph[0 + i] = src_octets[i];
            ph[4 + i] = dst_octets[i];
        }
        ph[9] = 0x06; // protocol is tcp
        let len_bytes = (self.0.len() as u16).to_be_bytes();
        ph[10] = len_bytes[0];
        ph[11] = len_bytes[1];
        self.0[16] = ph.iter().sum();
    }
}

pub enum IpVersion {
    V4,
    V6,
}

pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
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
    // use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};
    #[test]
    fn ipv4_checksum() {
        unimplemented!()
    }

    #[test]
    fn tcp_checksum() {
        unimplemented!()
    }
}
