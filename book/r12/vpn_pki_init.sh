cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa build-ca

# Certyfikat serwera
./easyrsa build-server server nopass
cp pki/ca.crt pki/issued/server.crt pki/private/server.key /etc/openvpn

# DH
./easyrsa gen-dh
mv pki/dh.pem /etc/openvpn/dh3072.pem

# tls-crypt-v2
openvpn --genkey tls-crypt-v2-server ta.key
cp ta.key /etc/openvpn

# client
./easyrsa build-client jurek nopass

