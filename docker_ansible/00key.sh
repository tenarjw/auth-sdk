#!/bin/bash

echo "przy tej konfiguracji założono, że klucz będzie bez hasła!"

ssh-keygen -t rsa -f ssh/ansible -C ansible
ssh-copy-id -i ssh/ansible.pub ansible@host1.example.com

exit 0