#!/bin/bash
# auth_scripts/activate_files.sh

echo "Przywracanie domyślnej konfiguracji (pliki lokalne)..."

# Zatrzymanie usług
systemctl stop sssd 
systemctl stop nslcd

# Przywrócenie /etc/nsswitch.conf do domyślnych wartości
sed -i 's/^passwd:.*$/passwd: files/' /etc/nsswitch.conf
sed -i 's/^group:.*$/group: files/' /etc/nsswitch.conf
sed -i 's/^shadow:.*$/shadow: files/' /etc/nsswitch.conf

echo "Konfiguracja oparta na plikach została przywrócona."