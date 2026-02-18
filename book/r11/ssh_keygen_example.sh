ssh-keygen -t ed25519 -f ~/.ssh/server3
ssh-copy-id -i ~/.ssh/server3.pub api@10.0.0.15
