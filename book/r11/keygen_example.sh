ssh-keygen -t ed25519 -f /home/api/.ssh/test -N ""
ssh-copy-id -i /home/api/.ssh/test.pub api@slave
