use async_std::io::{self};
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::core::upgrade::ProtocolName;
use libp2p::request_response::RequestResponseCodec;

use crate::MTU;
use crate::Packet;

#[derive(Clone, Default)]
pub struct PacketStreamProtocol;

impl ProtocolName for PacketStreamProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/ip4/0.0.0".as_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct PacketStreamCodec;

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
        let mut packet = [0u8; MTU];
        io.read(&mut packet).await?;
        Ok(packet)
    }

    async fn write_request<T>(
        &mut self,
        _: &PacketStreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write(&request).await?;
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
