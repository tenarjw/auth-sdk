echo "Domena:"
samba-tool domain info smb4.example.com

echo "KDC:"
wbinfo --ping-dc
wbinfo --online-status