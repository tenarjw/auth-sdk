#!/bin/bash
# Uruchom skrypt inicjalizacyjny
/setup/ldap/init_slapd.sh

# Upewnij się, że port 389 jest wolny
killall slapd 2>/dev/null || true

# Uruchom slapd jako główny proces
exec slapd -d 1 -h "ldap:/// ldapi:///" -f /etc/ldap/slapd.conf