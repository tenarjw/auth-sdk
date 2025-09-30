
echo "Test: Dodanie użytkownika i listowanie w LDAP i Sambie"

ADMINPASSWORD="Haslo123!"
SAMBASID=$(net getlocalsid | grep -o 'S-[0-9-]\+')

# Generowanie hasła użytkownika
echo "Użytkownik:"
read USERID
echo "Imię:"
read USERNAME
echo "Nazwisko:"
read USERSURNAME
echo "Hasło:"
read PASSWORD
HASH=$(slappasswd -s "$PASSWORD")

# Nastepny wolny numer UID
UIDNUMBER=10000
HIGHEST_UID=$(ldapsearch -x -H ldap://ldap.example.com \
    -D "cn=admin,dc=example,dc=com" \
    -b "ou=users,dc=example,dc=com" \
    -w "Haslo123!" "(objectClass=posixAccount)" uidNumber \
    | grep '^uidNumber:' \
    | awk '{print $2}' \
    | sort -n \
    | tail -1)

if [ -n "$HIGHEST_UID" ]; then
  UIDNUMBER=$((HIGHEST_UID+1 ))
fi
RID=$(( ( UIDNUMBER*2 ) + 1000 ))
SAMBASID=$(net getlocalsid | grep -o 'S-[0-9-]\+')

# Tworzenie pliku LDIF dla użytkownika
cat > /tmp/user.ldif <<EOF
dn: uid=$USERID,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: sambaSamAccount
cn: $USERNAME $USERSURNAME
sn: $USERSURNAME
givenName: $USERNAME
uid: $USERID
uidNumber: $UIDNUMBER
gidNumber: 100
homeDirectory: /home/$USERID
loginShell: /bin/bash
mail: $USERID@example.com
sambaSID: $SAMBASID-$RID
sambaAcctFlags: [U]
EOF


#userPassword: $HASH
# Dodanie użytkownika do LDAP
ldapadd -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -f /tmp/user.ldif

# Przekazanie hasła dwukrotnie do smbpasswd przez potok
(echo "$PASSWORD"; echo "$PASSWORD") | smbpasswd -a -s "$USERID"

# sssd
service sssd stop
sss_cache -E
service  sssd start

echo "Czekam na uruchomienie sssd..."
sleep 5

# Listowanie w LDAP
echo "Użytkownicy w LDAP:"
ldapsearch -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -b "uid=$USERID,ou=users,dc=example,dc=com"

# Daj chwilę sssd na połączenie z LDAP
sleep 3

# Listowanie w systemie
echo "Użytkownicy systemowi:"
getent passwd

# Test logowania Samba
echo "Test logowania Samba:"
smbclient -L //localhost -U $USERID%$PASSWORD

exit 0