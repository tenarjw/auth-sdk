ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcOverlay=ppolicy,olcDatabase={1}hdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=policies,dc=firma,dc=pl
EOF
