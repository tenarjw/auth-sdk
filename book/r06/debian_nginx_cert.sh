sudo chown www-data myCert.pem myCert.key
sudo chmod 600 myCert.key
sudo chmod 644 myCert.pem
sudo mkdir /etc/ssl/nginx
sudo chown www-data:root /etc/ssl/nginx
sudo chmod 710 /etc/ssl/nginx
sudo cp -p myCert.pem myCert.key /etc/ssl/nginx/
