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

Podmień wygenerowany IP (z Dockera) w pliku .ovpn na IP hosta.
Na przykład:
remote 192.168.100.3 1194

Nasyępnie:
openpvn jurek.ovpn

