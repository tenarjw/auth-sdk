openssl s_client -connect localhost:8443 \
  -CAfile ca/cacert.pem \
  -cert client.pem \
  -key client.key \
  -status -tlsextdebug
