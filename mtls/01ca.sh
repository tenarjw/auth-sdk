# zob. docker_ca
CA_PASSWORD="$(openssl rand -base64 12)"
#echo "$CA_PASSWORD">secret.txt
echo "secret">secret.txt
mkdir req
mkdir ca
docker run -i --rm -v "$(pwd)/ca:/ca" -v "$(pwd)/req:/req" myca ca
sudo chmod 777 req
echo "Password:"
cat secret.txt