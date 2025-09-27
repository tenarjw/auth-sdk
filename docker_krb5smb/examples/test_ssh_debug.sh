echo "Hasło: TwojeHaslo123!"
kdestroy
kinit Administrator@EXAMPLE.COM
ssh -vvv -o GSSAPIAuthentication=yes Administrator@smb4.example.com