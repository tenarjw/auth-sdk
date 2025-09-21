#!/bin/bash
# auth_scripts/activate_nslcd.sh

echo "Aktywacja konfiguracji NSLCD (lokalny LDAP)..."
sed -i 's/^passwd:.*$/passwd: files ldap/' /etc/nsswitch.conf
sed -i 's/^group:.*$/group: files ldap/' /etc/nsswitch.conf
sed -i 's/^shadow:.*$/shadow: files ldap/' /etc/nsswitch.conf

# Konfiguracja nslcd do połączenia z lokalnym serwerem slapd
cat > /etc/nslcd.conf <<EOF
uid nslcd
gid nslcd
uri ldap://127.0.0.1/
base dc=example,dc=com
EOF

echo "Restartowanie usługi NSLCD..."
systemctl restart nslcd
echo "Konfiguracja NSLCD została aktywowana."