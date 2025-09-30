#!/bin/sh

docker-compose down

sudo rm -rf ./data/ldap/*
docker-compose up -d
docker exec -it samba-ssh /examples/menu.sh