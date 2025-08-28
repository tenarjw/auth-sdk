
docker run -it --rm \
  --cap-add=NET_ADMIN --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv4.conf.all.send_redirects=0 \
  -v $(pwd)/openvpn:/etc/openvpn \
   myvpn client $1
