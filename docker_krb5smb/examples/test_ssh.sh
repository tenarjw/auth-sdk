echo "Dodałeś użytkownika nowy?"
echo "Hasło: Haslo123!"

# ticket:
kinit nowy@EXAMPLE.COM
klist
# loguje bez hasła?
ssh  -o GSSAPIAuthentication=yes nowy@smb4.example.com
