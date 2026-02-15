ldapmodify -x -ZZ -D "cn=admin,dc=firma,dc=pl" -W -H ldaps://10.0.0.217 <<EOF
dn: uid=uzytkownik,ou=Users,dc=firma,dc=pl
changetype: modify
replace: userPassword
userPassword: {SSHA}<hash>
EOF
