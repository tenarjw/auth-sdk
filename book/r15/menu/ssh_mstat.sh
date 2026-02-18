#!/bin/bash

# BEZPIECZNA OPERACJA Z UŻYCIEM SSH 
ssh -i ~/.ssh/admin admin@10.0.0.120 "/path/to/secure_script.sh"

echo "Naciśnij Enter, aby kontynuować..."
read -r

exit 0
