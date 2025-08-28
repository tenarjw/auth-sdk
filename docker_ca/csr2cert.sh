#!/bin/bash

cp $1.csr req
docker run -i --rm -v "$(pwd)/ca:/ca"  -v "$(pwd)/req:/req" myca csr $1

