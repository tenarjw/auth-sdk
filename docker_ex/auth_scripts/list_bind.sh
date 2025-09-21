#ldapsearch -x  -H ldap://10.0.0.217 -b dc=pwste,dc=edu,dc=pl
# -x Use simple authentication instead of SASL.
# -y file - password from file
IP=$(hostname -I)
ldapsearch -x -H ldap://$IP -b dc=example,dc=com -w adminpassword -D cn=admin,dc=example,dc=com
#ldapsearch -x -H ldap://$IP -b dc=example,dc=com -w adminpassword
