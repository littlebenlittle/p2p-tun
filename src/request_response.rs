use async_std::io::{self};
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response::RequestResponseCodec;
use std::convert::TryInto;

use crate::{Packet, MTU};

#[derive(Clone, Default)]
pub struct PacketStreamProtocol;

impl ProtocolName for PacketStreamProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/p2p-vpn/0.0.0".as_bytes()
    }
}

pub enum PacketRequest {
    // request to submit packet to network
    ToNet(Packet),
    // request to submit packet to TUN device
    ToTun(Packet),
}

impl PacketRequest {
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::with_capacity(1 + self.get_inner().len());
        data[0] = match self {
            Self::ToNet(_) => 0u8,
            Self::ToTun(packet) => 1u8,
        };
        data[1..].copy_from_slice(&self.get_inner().to_wire_format());
        data
    }

    pub fn from_wire_format(data: &[u8]) -> io::Result<Self> {
        let packet = Packet::from_wire_format(&data[1..])?;
        match data[0] {
            0 => Ok(Self::ToNet(packet)),
            1 => Ok(Self::ToTun(packet)),
            _ => Err(io::ErrorKind::InvalidData.into())
        }
    }

    fn get_inner(&self) -> &Packet {
        match self {
            Self::ToNet(packet) | Self::ToTun(packet) => packet,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketStreamCodec;

#[async_trait]
impl RequestResponseCodec for PacketStreamCodec {
    type Protocol = PacketStreamProtocol;
    type Request = PacketRequest;
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _: &PacketStreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // TODO should we use a length prefix if we know MTU?
        let vec = read_length_prefixed(io, MTU).await?;
        if vec.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        PacketRequest::from_wire_format(&vec)
    }

    async fn write_request<T>(
        &mut self,
        _: &PacketStreamProtocol,
        io: &mut T,
        request: PacketRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // TODO should we use a length prefix if we know MTU?
        write_length_prefixed(io, request.to_wire_format()).await?;
        io.close().await?;
        Ok(())
    }

    async fn read_response<T>(
        &mut self,
        _: &PacketStreamProtocol,
        _: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // should never receive response
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
        // no response
        Ok(())
    }
}
