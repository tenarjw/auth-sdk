#!/bin/bash
# auth_scripts/activate_sssd.sh

echo "Aktywacja konfiguracji SSSD..."

# Modyfikacja /etc/nsswitch.conf w celu użycia sss
sed -i 's/^passwd:.*$/passwd: files sss/' /etc/nsswitch.conf
sed -i 's/^group:.*$/group: files sss/' /etc/nsswitch.conf
sed -i 's/^shadow:.*$/shadow: files sss/' /etc/nsswitch.conf

# Tutaj definujemy konfigurację /etc/sssd/sssd.conf
# Na potrzeby przykładu tworzymy pusty, ale działający plik
mkdir -p /etc/sssd
chmod 0700 /etc/sssd
cat > /etc/sssd/sssd.conf <<EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = LOCAL

[nss]

[pam]

[domain/LOCAL]
id_provider = local
auth_provider = local
access_provider = permit
EOF
chmod 0600 /etc/sssd/sssd.conf

# Restart usługi
echo "Restartowanie usługi SSSD..."
systemctl restart sssd

echo "Konfiguracja SSSD została aktywowana."