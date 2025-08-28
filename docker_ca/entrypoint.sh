#!/bin/sh

set -e
: ${SUBJ:="/C=PL/CN=foo"}
: ${ALT:='DNS:foo.com'}
: ${POLICY='1.2.3.4'}

if [ -d "ca/private" ]
then
  echo "Exists"
else
   # CA DIR
#   mkdir -p ca/certs/
   mkdir -p ca/crl/
   mkdir -p ca/newcerts/
   mkdir -p ca/private/
   mkdir -p ca/requests/
   touch ca/index.txt
   sh -c "echo '1000' > ca/serial"

   # CA key
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes256  -pass file:secret.txt -out ca/private/cakey.pem

   # CA cert.
   openssl req -new -x509 -key ca/private/cakey.pem -out ca/cacert.pem -days 3650 \
    -passin file:secret.txt \
    -subj "$SUBJ" \
    -addext "subjectAltName = $ALT" 

fi

sed -i 's/.\/demoCA/\/ca/g' /etc/ssl/openssl.cnf
# countryName\t\t= match
#stateOrProvinceName\t= match
#organizationName\t= match


case "$1" in
    sh)
      /bin/sh
      ;;
    csr)
     cd /req
     ls -l *
     openssl ca -policy policy_anything -in $2.csr -out $2.crt
      ;;
    -- | ca)
      echo "Zainicjowano"
        ;;
    *)
        exec "$@"
esac

exit 1
