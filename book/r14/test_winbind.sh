# Sprawdzenie, czy winbind działa
wbinfo -p

# Lista użytkowników i grup z domeny
wbinfo -u
wbinfo -g

# Test uwierzytelnienia
wbinfo -a uzytkownik%haslo

# Zarządzanie bazą użytkowników Samby
pdbedit -L

# Informacje o domenie
net rpc info

# Mapowania ID
net idmap dump

# Zapytania NetBIOS
nmblookup -S serwer
nmblookup -A 10.0.0.217

# Test logowania do Samby
smbclient -L localhost -U uzytkownik%haslo
