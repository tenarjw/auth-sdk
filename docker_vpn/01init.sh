sudo docker build -t myvpn .

# skrypt entrypoint.sh zobaczy, że w /etc/openvpn nie ma plików, 
# skopiuje je z /usr/share/easy-rsa/ i /tmp do woluminu, 
#a następnie rozpocznie proces inicjalizacji.

docker run -it --rm \
    --cap-add=NET_ADMIN --device /dev/net/tun \
    -v $(pwd)/openvpn:/etc/openvpn \
    myvpn init