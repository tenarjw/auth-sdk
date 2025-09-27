echo "Hasło: TwojeHaslo123!"
# katalog domowy
mkdir -p /home/EXAMPLE/administrator

# na starcie brak krb.keytab
samba-tool domain exportkeytab /etc/krb5.keytab \
    --principal=HOST/smb4.example.com --principal=HOST/SMB4
chown root:root /etc/krb5.keytab
chmod 600 /etc/krb5.keytab

# weryfikacja:
klist -k /etc/krb5.keytab

# ticket:
kinit Administrator@EXAMPLE.COM
klist
# loguje bez hasła?
ssh -o GSSAPIAuthentication=yes Administrator@smb4.example.com
