import bcrypt
# pip install bcrypt

def password_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def password_verify(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)

stored_hash=password_hash('secret')
print('hash (secret): %s' % stored_hash)
print(password_verify('secret', stored_hash))
