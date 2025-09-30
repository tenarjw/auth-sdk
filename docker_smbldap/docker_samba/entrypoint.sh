#!/bin/bash

# Konfiguracja SSSD
echo "Konfiguracja SSSD"
cat > /etc/sssd/sssd.conf <<EOF
[sssd]
services = nss, pam
config_file_version = 2
domains = LDAP
debug_level = 6

[nss]
filter_groups = root
filter_users = root
debug_level = 6

[pam]
debug_level = 6

[domain/LDAP]
id_provider = ldap
auth_provider = ldap
ldap_uri = ldap://ldap.example.com
ldap_search_base = dc=example,dc=com
ldap_schema = rfc2307bis
ldap_default_bind_dn = cn=admin,dc=example,dc=com
ldap_default_authtok = Haslo123!
ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_group_object_class = posixGroup
ldap_group_name = cn
ldap_group_member = memberUid
enumerate = True
cache_credentials = True
ldap_tls_reqcert = allow
EOF
chown root:root /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/*
mkdir -p /var/lib/sss/db /var/lib/sss/pipes
chown -R sssd:sssd /var/lib/sss
pam-auth-update --enable sssd

# Konfiguracja PAM i NSS
pam-auth-update --enable sssd
sed -i '/^passwd:/ s/$/ sss/' /etc/nsswitch.conf
sed -i '/^group:/ s/$/ sss/' /etc/nsswitch.conf
sed -i '/^shadow:/ s/$/ sss/' /etc/nsswitch.conf

sed -i 's/DAEMON_OPTS="-D -f"/DAEMON_OPTS="-D"/g' /etc/default/sssd



ADMINPASSWORD="Haslo123!"
SAMBASID=$(net getlocalsid | grep -o 'S-[0-9-]\+')
UIDNUMBER=10000
RID=$(( (UIDNUMBER*2)+1000 ))
# dodaj pierwszego użytkownika
UPASSWORD="TestPass123!"
UHASH=$(slappasswd -s "$UPASSWORD")
USERID=testowy
USERNAME=User
USERSURNAME=Testowy
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
uidNumber: 1000
gidNumber: 100
homeDirectory: /home/$USERID
loginShell: /bin/bash
mail: $USERID@example.com
userPassword: $UHASH
sambaSID: $SAMBASID-$RID
sambaAcctFlags: [U]
EOF

ldapadd -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -f /tmp/user.ldif
(echo "$UPASSWORD"; echo "$UPASSWORD") | smbpasswd -a -s "$USERID"

# grupa
cat > /tmp/group.ldif <<EOF
dn: cn=testgroup,ou=groups,dc=example,dc=com
objectClass: posixGroup
objectClass: sambaGroupMapping
cn: testgroup
gidNumber: 1000
sambaSID: $SAMBASID
sambaGroupType: 2
memberUid: testowy
EOF
ldapadd -x -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -w $ADMINPASSWORD -f /tmp/group.ldif

# Uruchom demona sssd
sss_cache -E
service  sssd start

# Daj chwilę sssd na połączenie z LDAP
echo "Czekam na uruchomienie sssd..."
sleep 5

# Uruchom supervisord (który zarządza sshd i smbd)
echo "Uruchamiam supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf

