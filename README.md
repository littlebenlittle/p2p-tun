# P2P Tun

_Inspired by [hyprspace](https://github.com/hyprspace/hyprspace) and [kytan](https://github.com/changlan/kytan)_

Use a `tun` device for routing packets via `libp2p`.

## Status

This project is a WIP. It has **no security guarantees**. Please run in a VM or other machine you don't care about.

Currently capable of establishing a connection with explicit peer swarm addresses provided in config. See below for a description of how to create two `tun` devices and route packets between them over the p2p transport.

## Running

### Initialize the configuration

```sh
# initialize the configuration file
p2p-tun init --config myconfig.yaml
```

### Modify the config with VPN peer data

```yaml
# configA.yaml
# ...
peer_id: 12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq
swarm_addr: /ip4/127.0.0.1/tcp/9944
peer_routing_table:
  0.0.0.0/0: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
bootaddrs:
  12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW: /ip4/127.0.0.1/tcp/9955

# configB.yaml
# ...
peer_id: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
swarm_addr: /ip4/127.0.0.1/tcp/9955
peer_routing_table:
  0.0.0.0/0: 12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq
bootaddrs:
  12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq: /ip4/127.0.0.1/tcp/9955
```

### Run the app

```sh
# shell A
sudo p2p-tun run --config ./configA.yaml
# shell B
sudo p2p-tun run --config ./configB.yaml
```

### Configure netfilter

```sh
sudo ip addr add 10.0.1.10 dev tun0
sudo ip addr add 10.0.1.20 dev tun1
sudo ip route add 10.0.1.20 dev tun0
sudo ip route add 10.0.1.10 dev tun1
sudo iptables -t nat -A POSTROUTING -o tun0 -j SNAT --to 10.0.1.10
sudo iptables -t nat -A POSTROUTING -o tun1 -j SNAT --to 10.0.1.20
```

### Test Connection

```sh
# shell 1
nc -lvp 4040 10.0.1.20
# shell 2
nc 10.0.1.20 4040
```

## TODO

- [ ] modify netfilter rules automatically
- [ ] add property based tests
    - incoming and outgoing packets should not cause a `panic!`
    - packet sent should equal packet received with destination addr modified to match configured ip address of peer
    - should drop requests from peer that does not have an associated ip4 address
    - should not send packets to an ip4 address that does not have an associated peer id
- [ ] detect packet splitting due to improperly tuned MTU
- [ ] find a better way to split stuff that needs `root` (creating tun) from stuff that doesn't
