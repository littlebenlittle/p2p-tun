use crate::{Result, MTU};
use async_tun::{Tun as AsyncTun, TunBuilder};
use futures::io::{AsyncRead, AsyncWrite};

pub struct Tun(AsyncTun);

impl Tun {
    pub async fn new() -> Result<Tun> {
        Ok(Self(
            TunBuilder::new()
                .name("")
                .tap(false)
                .packet_info(false)
                .up()
                .mtu(MTU as i32)
                .try_build()
                .await?
        ))
    }
}

impl AsyncRead for Tun {}
impl AsyncWrite for Tun {}
