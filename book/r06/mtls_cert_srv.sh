openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage = serverAuth"

# Generowanie certyfikatu przez CA
docker run -i --rm -v "$(pwd)/ca:/ca" -v "$(pwd):/req" sign csr server
