sysctl -w net.ipv4.ip_forward=1

# ufw allow
ufw allow 1194/udp

W pliku /etc/default/ufw:
[12_w01_code_23.txt]
DEFAULT_FORWARD_POLICY="ACCEPT"
W pliku /etc/ufw/before.rules (przed # Don't delete...):
[12_w01_code_24.txt]
# START OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
Zastąp eth0 właściwym interfejsem sieciowym. Restart firewalla:
[12_w01_code_25.txt]
service ufw restart