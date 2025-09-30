#!/bin/bash

ADMINPASSWORD="Haslo123!"

# Test 1: Wyświetlenie wolumenów
echo "Test 1: Wyświetlenie wolumenów"
df -h | grep "/srv/samba/share"
ls -l /srv/samba/share

# Test 2: Sprawdzenie IP i nazw hostów
echo "Test 2: Sprawdzenie IP i nazw hostów"
ping -c 4 ldap.example.com

# Test 3: Sprawdzenie łączności z LDAP
echo "Test 3: Sprawdzenie łączności z LDAP"
nc -zv ldap.example.com 389
ldapsearch -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -b "dc=example,dc=com"


