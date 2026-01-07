docker stop postfilter
docker rm postfilter

docker run -it --log-opt mode=non-blocking --log-opt max-buffer-size=4m \
    --security-opt label=enable -p 25:25 -p 587:587 -p 465:465 -p 80:8081 -d -t --name postfilter \
    -e DOMAIN=twojadomena.com \
    -e HOSTNAME=mail.twojadomena.com \
    -e MY_HOSTNAME=mail.twojadomena.com \
    -e MY_DOMAIN=twojadomena.com \
    -e RELAY_HOST=smtp.office365.com  \
    -e RELAY_PORT=587 \
    -e RELAY_USER=your@twojadomena.com \
    -e RELAY_PASS=your_app_password \
    -e LETSENCRYPT_EMAIL=admin@twojadomena.com \
    postfilter:latest

# Lub smtp-relay.gmail.com
