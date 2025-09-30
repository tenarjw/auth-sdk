#!/bin/sh

docker network ls

# oczekiwany wynik:
# ............   docker_smbldap_my-net   bridge    local

docker network inspect my-net

