openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=client-app" \
  -addext "extendedKeyUsage = clientAuth"

# Generowanie certyfikatu przez CA
docker run -i --rm -v "$(pwd)/ca:/ca" -v "$(pwd):/req" sign csr client
