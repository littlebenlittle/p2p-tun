use crate::MTU;
use async_tun::{Tun as AsyncTun, TunBuilder};
use core::result::Result;
use futures::{
    io::{AsyncRead, AsyncWrite, Error},
    task::{Context, Poll},
};
use std::pin::Pin;

/// Wrapper around async-tun that implements AsyncRead and AsyncWrite
pub struct Tun(AsyncTun);

impl Tun {
    pub async fn new() -> crate::Result<Tun> {
        Ok(Self(
            TunBuilder::new()
                .name("")
                .tap(false)
                .packet_info(false)
                .up()
                .mtu(MTU as i32)
                .try_build()
                .await?,
        ))
    }
}

impl AsyncRead for Tun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut futures::task::Context<'_>,
        buf: &mut [u8],
    ) -> futures::task::Poll<Result<usize, Error>> {
        Pin::new(&mut self.0.reader()).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0.writer()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0.writer()).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0.writer()).poll_close(cx)
    }
}
