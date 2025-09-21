#!/bin/bash

docker run --rm \
  -v "$(pwd)/playbooks:/runner/project" \
  -v "$(pwd)/inventory:/runner/inventory" \
  -v "$(pwd)/ssh:/home/ansible/.ssh" \
  ansadmin:latest \
  "ansible-playbook -i /runner/inventory/hosts /runner/project/date.yml"

exit 0