samba-tool user create nowy Haslo123!
samba-tool group add grupa1
samba-tool group addmembers grupa1 nowy
echo "Sprawdzamy:"
samba-tool user list
samba-tool group list

