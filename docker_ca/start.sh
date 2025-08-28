#docker rmi myca
#sudo rm -R -f myca
docker build -t myca .

docker run -i --rm -v "$(pwd)/ca:/ca" -v "$(pwd)/req:/req" myca ca
sudo chmod 777 req