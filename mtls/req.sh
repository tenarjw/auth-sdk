#!/bin/bash

echo "Request for $1"
cp $1.csr req
sudo docker run -i --rm -v "$(pwd)/ca:/ca"  -v "$(pwd)/req:/req" myca csr $1

