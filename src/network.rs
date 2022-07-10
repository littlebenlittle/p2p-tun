
use async_std::{fs::File, os::unix::io::FromRawFd};
use futures::{
    io::{AsyncRead, AsyncWrite, Error},
    task::{Context, Poll},
};
use std::{io, net::Ipv4Addr, pin::Pin};

/// an IP network device
pub struct Network<'a> {
    fd: File,
    pin: Pin<&'a mut File>,
    ipv4_addr: Ipv4Addr,
}

impl<'a> Network<'a> {
    /// create a new network device and resolve
    /// its ipv4 address using ARP
    pub fn new() -> io::Result<Self> {
        // based on https://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html
        const ETH_P_IP: u16 = 0x0800;
        use libc::{socket, AF_PACKET, SOCK_RAW};
        let fd = unsafe {
            match socket(AF_PACKET, SOCK_RAW, ETH_P_IP.to_be() as i32) {
                -1 => return Err(io::Error::last_os_error()),
                fd => File::from_raw_fd(fd),
            }
        };
        let ipv4_addr: Ipv4Addr = {
            //TODO do ARP request
        };
        Ok(Self {
            pin: Pin::new(&mut fd),
            fd,
            ipv4_addr,
        })
    }

    pub fn get_ipv4_addr(&self) -> &Ipv4Addr {
        return &self.ipv4_addr;
    }
}

impl<'a> AsyncRead for Network<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut futures::task::Context<'_>,
        buf: &mut [u8],
    ) -> futures::task::Poll<core::result::Result<usize, Error>> {
        // TODO strip layer 2 headers
        self.pin.poll_read(cx, buf)
    }
}

impl<'a> AsyncWrite for Network<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, Error>> {
        // TODO add layer 2 headers
        self.pin.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.pin.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.pin.poll_close(cx)
    }}
