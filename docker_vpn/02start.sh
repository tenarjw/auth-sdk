docker run -it -d \
   --name vpn-server \
   --cap-add=NET_ADMIN --device /dev/net/tun \
   -p 1194:1194/udp \
   -v $(pwd)/openvpn:/etc/openvpn \
   myvpn start    