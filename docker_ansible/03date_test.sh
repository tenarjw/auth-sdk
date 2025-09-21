#!/bin/bash

# test lokalnie - pod warunkiem, że masz zainstalowany ansible"

ansible-playbook -i $(pwd)/inventory/hosts $(pwd)/playbooks/date.yml

exit 0