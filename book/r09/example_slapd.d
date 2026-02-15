ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={1}hdb,cn=config
changetype: add
objectClass: olcDatabaseConfig
objectClass: olcHdbConfig
olcDatabase: {1}hdb
olcSuffix: dc=firma,dc=pl
olcRootDN: cn=admin,dc=firma,dc=pl
olcRootPW: {SSHA}<hash>
olcDbDirectory: /var/lib/ldap
olcDbIndex: objectClass eq
olcDbIndex: uid eq
EOF
