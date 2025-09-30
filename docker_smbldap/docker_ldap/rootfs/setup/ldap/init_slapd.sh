#!/bin/bash
export LDAP_ROOTPW="Haslo123!"
export ROOTPW=$(slappasswd -s "$LDAP_ROOTPW")

# Zastąp linię rootpw w pliku slapd.conf
sed -i "s|rootpw.*|rootdn \"cn=admin,dc=example,dc=com\"\nrootpw ${ROOTPW}|g" /setup/ldap/slapd.conf

# Skopiuj plik konfiguracyjny
cp /setup/ldap/slapd.conf /etc/ldap/

# Zaktualizuj plik /etc/default/slapd
sed -i "s|SLAPD_CONF=/|SLAPD_CONF=/etc/ldap/slapd.conf|g" /etc/default/slapd

# Ustaw uprawnienia
chown openldap:openldap /etc/ldap/slapd.conf
chmod 640 /etc/ldap/slapd.conf
chown -R openldap:openldap /var/lib/ldap
chmod -R 700 /var/lib/ldap

# Przetestuj konfigurację
slaptest -f /etc/ldap/slapd.conf -v
if [ $? -ne 0 ]; then
    echo "Błąd w konfiguracji slapd.conf"
    exit 1
fi

# Upewnij się, że slapd nie działa
/etc/init.d/slapd stop
killall slapd 2>/dev/null || true

# Sprawdź, czy baza danych zawiera wpis dc=example,dc=com
echo "Sprawdzanie, czy baza danych LDAP jest zainicjowana..."
ldapsearch -x -H ldap://localhost -D "cn=admin,dc=example,dc=com" -w "$LDAP_ROOTPW" -b "dc=example,dc=com" -s base > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Inicjalizacja bazy danych..."
    # Usuń istniejącą bazę danych, jeśli istnieje
    rm -rf /var/lib/ldap/*
    slapadd -n 1 -l /dev/null -f /etc/ldap/slapd.conf

    # Utwórz plik LDIF dla podstawowej struktury
    cat > /tmp/init.ldif <<EOF
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
dc: example
o: Example Organization

dn: cn=admin,dc=example,dc=com
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: admin
userPassword: ${ROOTPW}
description: LDAP administrator

dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups
EOF

    # Załaduj strukturę
    slapadd -l /tmp/init.ldif -f /etc/ldap/slapd.conf
    if [ $? -ne 0 ]; then
        echo "Błąd podczas ładowania pliku LDIF"
        exit 1
    fi

    # Ustaw uprawnienia
    chown -R openldap:openldap /var/lib/ldap
    chmod -R 700 /var/lib/ldap

fi

# Uruchom slapd
/etc/init.d/slapd start