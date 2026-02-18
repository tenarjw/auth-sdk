python3 -c 'import bcrypt; print(bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode())'
