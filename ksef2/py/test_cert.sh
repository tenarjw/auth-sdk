openssl pkcs12 -in $(pwd)/cert.pfx  -nodes \
    -passin pass:"pass123" | openssl x509 -noout -subject
