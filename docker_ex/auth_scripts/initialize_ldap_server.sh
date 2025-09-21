#!/bin/bash
# auth_scripts/initialize_ldap_server.sh

# --- Zmienne konfiguracyjne ---
LDAP_DOMAIN="example.com"
LDAP_ORGANIZATION="Example Inc"
LDAP_ADMIN_PASSWORD="adminpassword"
LDAP_BASE_DN=$(echo "dc=$LDAP_DOMAIN" | sed 's/\./,dc=/g')

echo "Rozpoczynanie konfiguracji serwera OpenLDAP..."

# Minimalna konfiguracja debconf, aby tylko utworzyć strukturę
echo "slapd slapd/domain string $LDAP_DOMAIN" | debconf-set-selections
echo "slapd slapd/organization string $LDAP_ORGANIZATION" | debconf-set-selections
# Celowo pomijamy hasło tutaj, ustawimy je ręcznie
echo "slapd slapd/root_password password " | debconf-set-selections
echo "slapd slapd/root_password_again password " | debconf-set-selections
echo "slapd slapd/backend select MDB" | debconf-set-selections

# Usunięcie starej konfiguracji, jeśli istnieje, dla czystego startu
rm -rf /etc/ldap/slapd.d/*
rm -rf /var/lib/ldap/*
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure slapd

echo "Uruchamianie usługi slapd z podstawową konfiguracją..."
systemctl start slapd
sleep 2

# --- NOWA, NIEZAWODNA METODA USTAWIANIA HASŁA ---
echo "Ustawianie hasła administratora za pomocą ldapmodify..."
# Generowanie hasha hasła
HASHED_PASSWORD=$(slappasswd -h {SSHA} -s "$LDAP_ADMIN_PASSWORD")

# Tworzenie pliku LDIF do zmiany hasła
cat > /tmp/change_password.ldif <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: ${HASHED_PASSWORD}
-
replace: olcRootDN
olcRootDN: cn=admin,${LDAP_BASE_DN}
EOF

# Modyfikacja konfiguracji "na żywo" za pomocą SASL/EXTERNAL przez gniazdo unix
# To pozwala na modyfikację jako root bez podawania starego hasła
ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/change_password.ldif

if [ $? -ne 0 ]; then
    echo "KRYTYCZNY BŁĄD: Nie udało się ustawić hasła administratora LDAP."
    exit 1
fi
echo "Hasło administratora zostało poprawnie ustawione."
# --- KONIEC NOWEJ METODY ---


# Tworzenie pliku LDIF z podstawową strukturą
cat > /tmp/base_structure.ldif <<EOF
dn: ou=people,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: people

dn: ou=groups,${LDAP_BASE_DN}
objectClass: organizationalUnit
ou: groups
EOF

# Dodawanie struktury do LDAP z nowym, poprawnie ustawionym hasłem
echo "Dodawanie podstawowej struktury (ou=people, ou=groups)..."
ldapadd -x -D "cn=admin,${LDAP_BASE_DN}" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/base_structure.ldif

if [ $? -eq 0 ]; then
    echo "SUKCES: Serwer LDAP został pomyślnie zainicjowany."
else
    echo "BŁĄD: Wystąpił problem podczas dodawania struktury do LDAP."
fi

# Czyszczenie
rm /tmp/change_password.ldif
rm /tmp/base_structure.ldif