echo "Pamietaj by podac Common Name"
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr
sudo ./req.sh server
cp ./ca/newcerts/1001.pem server.pem

