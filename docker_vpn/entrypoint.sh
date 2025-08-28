#!/bin/bash

set -e

HOME="/etc/openvpn"
EASYRSA_HOME="$HOME/easy-rsa"
CONFIG="$HOME/server.conf"

export EASYRSA="$EASYRSA_HOME"

# Check if the easy-rsa directory already exists in the persistent volume.
# This ensures that it's set up correctly on the first run.
if [ ! -d "$EASYRSA_HOME" ]; then
    echo "Creating Easy-RSA directory and copying files to persistent volume..."
    mkdir -p "$EASYRSA_HOME"
    cp -r /usr/share/easy-rsa/* "$EASYRSA_HOME/"
fi

# Check if the server.conf file exists in the persistent volume.
if [ ! -f "$CONFIG" ]; then
    echo "Copying server.conf to persistent volume..."
    cp /tmp/server.conf "$CONFIG"
fi

ini_vpn(){
  echo "Initializing VPN setup..."

  cd "$EASYRSA_HOME"

  ./easyrsa init-pki
  cp /tmp/vars "$EASYRSA_HOME/pki/vars"

  dd if=/dev/urandom of="$EASYRSA_HOME/pki/.rnd" bs=256 count=1

  ./easyrsa --batch build-ca nopass
  ./easyrsa --batch gen-req server nopass
  ./easyrsa --batch sign-req server server
  ./easyrsa gen-crl
  ./easyrsa gen-dh

  openvpn --genkey --secret "$HOME/tc.key"

  cp "$EASYRSA_HOME/pki/ca.crt" "$HOME/"
  cp "$EASYRSA_HOME/pki/crl.pem" "$HOME/"
  cp "$EASYRSA_HOME/pki/private/server.key" "$HOME/"
  cp "$EASYRSA_HOME/pki/issued/server.crt" "$HOME/"
  cp "$EASYRSA_HOME/pki/dh.pem" "$HOME/"
  
  echo "VPN initialization complete."
}


start_vpn () {
    echo "Starting OpenVPN server..."
    openvpn --writepid /run/openvpn.pid \
        --cd "$HOME" \
        --config "$CONFIG"
}

ovpn () {
  OVPN_DEVICE=tun
  OVPN_IP=$(hostname -I | awk '{print $1}')
  
  if [ -z "$OVPN_IP" ]; then
    OVPN_IP="127.0.0.1"
  fi

  cn=$1
  
  cd "$EASYRSA_HOME"
  
#  echo "Generating client configuration for $cn..."
  
  cat << EOF
client
dev $OVPN_DEVICE
proto udp
remote $OVPN_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
verb 3
<ca>
$(cat "$HOME/ca.crt")
</ca>
<cert>
$(openssl x509 -in pki/issued/${cn}.crt)
</cert>
<key>
$(cat pki/private/${cn}.key)
</key>
key-direction 1
<tls-crypt>
$(cat "$HOME/tc.key")
</tls-crypt>
EOF
#  echo "Client configuration generated."
}

case "$1" in
  init)
    ini_vpn
    ;;
  start)
    start_vpn
    ;;
  client)
    cd "$EASYRSA_HOME"
    ./easyrsa --batch gen-req $2 nopass
    ./easyrsa --batch sign-req  client $2
# stary    ./easyrsa build-client-full "$2" nopass
    ;;
  ovpn)
    ovpn "$2"
    ;;
  *)
   exec "$@"
esac