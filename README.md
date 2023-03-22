# P2P Tun

_Inspired by [hyprspace](https://github.com/hyprspace/hyprspace) and [kytan](https://github.com/changlan/kytan)_

Use a `tun` device for routing packets via `libp2p`.

## Status

This project is a WIP. It does not currently work.

## Running

### Initialize the configuration

```sh
# initialize the configuration file
p2p-tun init --config myconfig.yaml
```

### Modify the config with VPN peer data

```yaml
# ...
peers:
  - peer_id: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
    swarm_addr: /ip4/127.0.0.1/tcp/9955
    ip4_addr: 10.0.1.10
```

### Run the app

```sh
p2p-tun run --config ./config.yaml
```

### Configure netfilter

```sh
sudo ip route add 10.0.1.10 dev tun0
sudo iptables -t nat -A POSTROUTING -o tun0 -j SNAT --to 10.0.1.1
```

## TODO

- [ ] handle packet modification with [etherparse](https://docs.rs/etherparse/latest/etherparse/)
- [ ] add property based tests
    - incoming and outgoing packets should not cause a `panic!`
    - packet sent should equal packet received with destination addr modified to match configured ip address of peer
    - should drop requests from peer that does not have an associated ip4 address
    - should not send packets to an ip4 address that does not have an associated peer id
- [ ] detect packet splitting due to improperly tuned MTU
