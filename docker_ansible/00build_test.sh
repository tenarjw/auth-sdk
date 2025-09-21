#!/bin/bash


docker run --rm -it \
  -v "$(pwd)/playbooks:/runner/project"  \
  -v "$(pwd)/inventory:/runner/inventory"  \
  -v "$(pwd)/ssh:/home/ansible/.ssh"   \
  ansadmin:latest   bash


exit 0