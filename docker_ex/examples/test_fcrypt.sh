#!/bin/bash

python fcrypt_test.py rsa
python fcrypt_test.py crypt fcrypt.py encrypted.dat
python fcrypt_test.py decrypt encrypted.dat decrypted.txt
more decrypted.txt

