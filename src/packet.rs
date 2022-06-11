// TODO: add req/res to change MTU
pub const PACKET_LEN: usize = 1500;

#[derive(Debug, Clone)]
pub struct Packet(pub [u8; PACKET_LEN]);

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        packet.0.into()
    }
}

#[derive(Debug)]
pub enum Error {
    Overflow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Error::Overflow => formatter.write_str("packet overflow"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}"))
    }
}

impl TryInto<Packet> for Vec<u8> {
    type Error = Error;
    fn try_into(self) -> Result<Packet, Self::Error> {
        if self.len() > PACKET_LEN {
            return Err(Error::Overflow);
        }
        let mut packet = [0u8; PACKET_LEN];
        packet[..self.len()].copy_from_slice(&self[..]);
        Ok(Packet(packet))
    }
}

