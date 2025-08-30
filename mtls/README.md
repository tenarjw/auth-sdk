1) ./01ca.sh
2) Certificates:
- Must fill: Common Name (for test: localhost)
- Pass phrase for cakey.pem: see secret.txt
- Sign the certificate? [y/n]:y
- commends:
sudo ./02req1cl.sh
sudo ./02req1s.sh
3) sudo apt install golang-go
03test1s.sh
3) another console:
./04test1cl.sh

Result:
* Connection #0 to host localhost left intact
Hello World
