# Start

./00folder.sh
./01init.sh
./02start.sh

# Test

**IP**
docker inspect vpn-server | grep IPAddress

## Network
sysctl -w net.ipv4.ip_forward=1
ufw allow 1194/udp

## Create config
user: "jurek"

./03client.sh jurek
./04ovpn.sh jurek >jurek.ovpn

## Connect

openpvn jurek.ovpn