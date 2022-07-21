use async_std::{fs::File, os::unix::io::FromRawFd};
use futures::{
    io::{AsyncRead, AsyncWrite, Error},
    task::{Context, Poll},
};
use std::{io, pin::Pin};
use core::result::Result;

/// an IP network device
pub struct Network(File);

impl Network {
    pub fn new() -> io::Result<Self> {
        // based on https://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html
        // see also https://man7.org/linux/man-pages/man7/packet.7.html
        const ETH_P_IP: u16 = 0x0800;
        use libc::{socket, AF_PACKET, SOCK_DGRAM};
        unsafe {
            match socket(AF_PACKET, SOCK_DGRAM, ETH_P_IP.to_be() as i32) {
                -1 => Err(io::Error::last_os_error()),
                fd => Ok(Self(File::from_raw_fd(fd)))
            }
        }
    }
}

impl AsyncRead for Network {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut futures::task::Context<'_>,
        buf: &mut [u8],
    ) -> futures::task::Poll<Result<usize, Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Network {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
