# P2P Tun

_Inspired by [hyprspace](https://github.com/hyprspace/hyprspace) and [kytan](https://github.com/changlan/kytan)_

Use a `tun` device for routing packets via `libp2p`.

## Status

This project is a WIP. It does not currently work.

## Running

### Create a `tun ` device

```sh
# Create a TUN device named "mytun"
ip tuntap add mode tun dev mytun
# Set the IP address for the TUN device
ip addr add 10.0.1.1/24 dev mytun
# Bring the TUN device up
ip link set mytun up
```

### Initialize the configuration

```sh
# initialize the configuration file
p2p-tun init --config myconfig.yaml
```

Modify the config with VPN peer data

```yaml
# ...
peers:
  - ip: 10.0.1.10
    peer_id: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
```

```sh
p2p-tun run --config ./config.yaml --dev mytun
```

## TODO

- [ ] handle packet modification with [etherparse](https://docs.rs/etherparse/latest/etherparse/)
- [ ] add property based tests
    - incoming and outgoing packets should not cause a `panic!`
    - packet sent should equal packet received with destination addr modified to match configured ip address of peer
    - should drop requests from peer that does not have an associated ip4 address
    - should not send packets to an ip4 address that does not have an associated peer id
- [ ] detect packet splitting due to improperly tuned MTU
