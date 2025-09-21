#!/bin/bash

/auth_scripts/activate_files.sh
/auth_scripts/test_auth.sh einstein # Teraz nie powinien go znaleźć
/auth_scripts/test_auth.sh root     # Ale root nadal będzie dostępny