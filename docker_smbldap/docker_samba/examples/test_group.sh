#!/bin/bash

echo "Test: Dodanie grupy i listowanie w LDAP i Sambie"

ADMINPASSWORD="Haslo123!"

# Generowanie hasła użytkownika
PASSWORD="TestPass123!"
HASH=$(slappasswd -s "$PASSWORD")

# Tworzenie pliku LDIF dla grupy
cat > /tmp/group.ldif <<EOF
dn: cn=testgroup,ou=groups,dc=example,dc=com
objectClass: posixGroup
objectClass: sambaGroupMapping
cn: testgroup
gidNumber: 1000
sambaSID: S-1-5-21-1000-1000-1000-2000
sambaGroupType: 2
memberUid: testuser
EOF

# Dodanie  grupy do LDAP
ldapadd -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -f /tmp/group.ldif

# Listowanie w LDAP
echo "Grupy w LDAP:"
ldapsearch -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -b "cn=testgroup,ou=groups,dc=example,dc=com"

# Listowanie w Sambie

echo "Grupy w Sambie:"
net groupmap list

# Weryfikacja grup LDAP w Sambie
echo "Weryfikacja grup LDAP w Sambie"
id testuser
getent group testgroup

# Test dostępu do udziału z ograniczeniem grupowym
echo "Dodawanie udziału z ograniczeniem grupowym"
cat >> /etc/samba/smb.conf <<EOF
[testshare]
path = /srv/samba/share
valid users = @testgroup
read only = no
EOF
service samba restart
echo "Test dostępu do udziału:"
smbclient //localhost/testshare -U testuser%$PASSWORD

exit 0