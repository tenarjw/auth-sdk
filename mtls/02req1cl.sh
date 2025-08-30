echo "Pamietaj by podac Common Name"
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr
sudo ./req.sh client
cp ./ca/newcerts/1000.pem client.pem

