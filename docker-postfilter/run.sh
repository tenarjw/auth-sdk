docker stop postfilter
docker rm postfilter

docker run -it --log-opt mode=non-blocking --log-opt max-buffer-size=4m \
    --security-opt label=enable  -p 587:587 -p 80:8081 -d -t --name postfilter \
    -e TEST_MODE=true \
    -e DOMAIN=mail.example.com \
    -e HOSTNAME=mail.example.com \
    -e MY_HOSTNAME=mail.example.com \
    -e MY_DOMAIN=mail.example.com \
    -e RELAY_HOST=smtp.office365.com  \
    -e RELAY_PORT=587 \
    -e RELAY_USER=your@example.com \
    -e RELAY_PASS=your_app_password \
    -e SASL_USER=user@example.com \
    -e SASL_PASS=BArdZO_trudne234 \
    -e LETSENCRYPT_EMAIL=admin@example.com \
    postfilter:latest
