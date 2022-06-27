# P2P Tun

_Inspired by [hyprspace](https://github.com/hyprspace/hyprspace) and [kytan](https://github.com/changlan/kytan)_

Create a `tun` device for routing packets via `libp2p`.

## Status

This project is a WIP. It does not currently work.

## Running

Initialize the configuration

```sh
# create a user for p2p-tun
sudo useradd -M -s /sbin/nologin p2ptun
# initialize the configuration file
p2p-tun init
```

Modify the config with VPN peer data

```yaml
# ...
peers:
  - ip: 10.1.1.10
    peer_id: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
```

```sh
# must be run with elevated privileges to create the TUN virtual device
# effective user will be changed before the p2p swarm starts
sudo p2p-tun run --config ./config.yaml
```

```sh
# update routing table to route packets to newly create TUN device
ip route add 10.1.1.1 dev tun0
ip route add 10.1.1.0/24 via 10.1.1.1
```

## TODO

- [] separate management of TUN from management of swarm transport
- [] handle packet modification with [etherparse](https://docs.rs/etherparse/latest/etherparse/)
- [] add property based tests
    - incoming and outgoing packets should not cause a `panic!`
    - packet sent should equal packet received with destination addr modified to match configured ip address of peer
    - should not receive packets from peer that does not have an associated ip4 address
    - should not send packets to an ip4 address that does not have an associated peer id
