openssl genrsa -des3 -out cert.pkey 2048
openssl rsa -in cert.pkey -out cert.key
openssl req -new -key cert.key -out cert.csr
openssl x509 -req -days 365 -in cert.csr -signkey cert.key -out cert.crt
