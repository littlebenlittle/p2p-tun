# P2P Tun

_Inspired by [hyprspace](https://github.com/hyprspace/hyprspace) and [kytan](https://github.com/changlan/kytan)_

Use a `tun` device for routing packets via `libp2p`.

## Status

This project is a WIP. It has **no security guarantees**. Please run in a VM or other machine you don't care about.

Currently capable of establishing a connection with explicit peer swarm addresses provided in config. See below for a description of how to create two `tun` devices and route packets between them over the p2p transport.

## Running

This example setup is for two VMs running on a VLAN 192.168.122.0/24.

### Init Config on both VMs

On both VMs:

```sh
p2p-tun init --config config.yaml
```

### Modify config on both VMs

```yaml
# config.yaml of VM A
# ...
peer_id: 12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq
swarm_addr: /ip4/192.168.122.10/tcp/9955
peer_routing_table:
  0.0.0.0/0: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
bootaddrs:
  12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW: /ip4/192.168.122.20/tcp/9955
```

```yaml
# config.yaml of VM B
# ...
peer_id: 12D3KooWBWtFDCDJqDLLd8LDDYU7EuFXEGj34HnpRQ8psfYadboW
swarm_addr: /ip4/192.168.122.20/tcp/9955
peer_routing_table:
  0.0.0.0/0: 12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq
bootaddrs:
  12D3KooWRd9wxyHnUae7fxVjYV5hDm1CuTwrAxKhYVwGd6Eu4Ssq: /ip4/192.168.122.10/tcp/9955
```

### Run the app

On both VMs:

```sh
sudo p2p-tun --config ./config.yaml run
```

### Configure netfilter

On VM A:

```sh
sudo /sbin/ip addr add 10.8.0.1 dev tun0
sudo /sbin/route add -host 10.8.0.2 dev tun0
sudo /sbin/ifconfig tun0 10.8.0.1 up
```

On VM B:

```sh
sudo /sbin/ip addr add 10.8.0.2 dev tun1
sudo /sbin/route add -host 10.8.0.1 dev tun1
sudo /sbin/ifconfig tun1 10.8.0.2 up
```

### Test Connection

VM A:

```sh
nc -lv 10.8.0.1 9999
```

VM B:

```sh
nc 10.8.0.1 9999
```

## TODO

- [ ] configure netfilter automatically
- [ ] add property based tests
    - incoming and outgoing packets should not cause a `panic!`
    - packet sent should equal packet received
    - should drop requests from peer that does not have an associated ip4 address
    - should not send packets to an ip4 address that is not in the CIDR range of an associated peer id
- [ ] detect packet splitting due to improperly tuned MTU
- [ ] find a better way to split stuff that needs `root` (creating tun) from stuff that doesn't
