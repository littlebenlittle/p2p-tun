///This was mostly written by ChapGPT, so fingers crossed? Looks OK...

use libc::{ioctl, c_short};
use nix::request_code_none;
use async_std::fs::{File, OpenOptions, };
use std::os::fd::AsRawFd;
use std::error::Error;

const TUNSETIFF: u64 = request_code_none!(b'T', 202);
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;
const IFNAMSIZ: usize = 16;

pub async fn new(dev: impl AsRef<str>) -> Result<File, Box<dyn Error + Sync + Send>> {
    let tun_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .await?;
    let tun_raw_fd = tun_fd.as_raw_fd();
    let mut ifr = tun_iface_request(dev.as_ref());

    unsafe {
        let rc = ioctl(tun_raw_fd, TUNSETIFF, &mut ifr);
        if rc < 0 {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
    }
    Ok(tun_fd)
}

fn tun_iface_request(ifname: &str) -> IfReq {
    let mut ifr = IfReq::default();
    ifr.ifr_name[..ifname.len()].copy_from_slice(ifname.as_bytes());
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    ifr
}

#[repr(C)]
#[derive(Default)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: c_short,
}
