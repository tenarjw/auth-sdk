#openssl x509 -in $(pwd)/pansp.pem -noout -subject -nameopt RFC2253
openssl pkcs12 -in $(pwd)/cert.pfx -nodes -passin pass:"pass123" | openssl x509 -noout -subject