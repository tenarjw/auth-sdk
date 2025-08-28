echo "Remember about Common Name !!!"
#openssl req -new -newkey rsa:2048 -nodes -keyout example.com.key -out example.com.csr
./csr2cert.sh example.com

cp ca/newcerts/1000.pem example.pem