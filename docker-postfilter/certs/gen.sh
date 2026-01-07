openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout mail.key \
    -out mail.crt \
    -subj "/CN=mail.examle.com"


cat mail.crt mail.key > mail.pem
chmod 600 mail.pem