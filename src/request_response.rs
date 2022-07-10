use async_std::io::{self};
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response::RequestResponseCodec;

use crate::{Packet, MTU};

#[derive(Clone, Default)]
pub struct PacketStreamProtocol;

impl ProtocolName for PacketStreamProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/p2p-vpn/0.0.0".as_bytes()
    }
}

#[derive(Debug)]
pub enum PacketRequest {
    /// data from a local peer destined for a remote service
    Remote(Vec<u8>),
    /// data from a remote service destined for the local peer
    Local(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub enum Destination {
    // request to submit packet to network
    Net,
    // request to submit packet to TUN device
    Tun,
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
