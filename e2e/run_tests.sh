#!/bin/sh

set -e

if [ ! -d "$PWD/e2e" ]; then
    echo "run script from root of p2p-tun project"
    exit 1
fi
cd e2e || exit 1

# use docker-compose to run commands
# start containers
docker-compose up 

# configure peers
docker-compose exec -i client-peer p2p-tun init
docker-compose exec -i exit-peer p2p-tun init
CLIENT_PEER_ID=$(docker-compose exec -i client-peer p2p-tun query peerid)
EXIT_PEER_ID=$(docker-compose exec -i exit-peer p2p-tun query peerid)
docker-compose exec -i client-peer p2p-tun config push --peer 10.1.1.0/24:"$EXIT_PEER_ID"
docker-compose exec -i exit-peer   p2p-tun config push --exit "$CLIENT_PEER_ID"

# run vpn peers
TUN=$(docker-compose exec -i client-peer p2p-tun run --daemon --print-device)
docker-compose exec exit-peer p2p-tun run --daemon

# configure ip4 routes on client
docker-compose exec client-peer ip route add 10.1.2.1/32 dev "$TUN"
docker-compose exec client-peer ip route add 0.0.0.0/0 via 10.1.1.1

# pause and then run ping on client
docker-compose exec client-peer sh -c "sleep 1 && p2p-tun-e2e ping service"

# listen for incoming TCP connection on service
STATUS=$(docker-compose exec -i service p2p-tun-e2e listen --expect exit-peer)

# clean up
docker-compose down

if [ -z "$STATUS" ]
   then echo "test passed"
   else echo "test failed" && exit 1
fi
