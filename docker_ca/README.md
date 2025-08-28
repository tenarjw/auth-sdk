# Start:

1) set secret.txt

2) demoCA -> ca
sudo sed -i 's/.\/demoCA/\/ca/g' /etc/ssl/openssl.cnf

3) ./start.sh

# Test

./test1.sh
