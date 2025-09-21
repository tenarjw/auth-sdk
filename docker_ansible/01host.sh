#!/bin/bash

ssh-keyscan -H host1.example.com >> ./ssh/known_hosts
chmod 644 ./ssh/known_hosts

exit 0