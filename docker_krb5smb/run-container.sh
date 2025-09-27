#!/bin/sh

docker stop samba-kerberos-ssh 2>/dev/null || true
docker rm samba-kerberos-ssh 2>/dev/null || true

# Create volume
docker volume rm samba-data
docker volume create samba-data

# start container
docker run -d \
  -p 22:22 -p 88:88 -p 135:135 -p 137-139:137-139 -p 445:445 -p 389:389 -p 636:636 -p 464:464 -p 3268-3269:3268-3269 \
  --hostname smb4.example.com \
  --name samba-kerberos-ssh \
  --cap-add SYS_ADMIN \
  --security-opt apparmor:unconfined \
  --mount type=volume,src=samba-data,dst=/var/lib/samba \
  samba-kerberos-ssh
 
# Exec menu  
docker exec -it samba-kerberos-ssh /examples/menu.sh