#!/usr/bin/python
#-*- coding: utf-8 -*-
import hashlib
import os

def password_hash(password):
    salt = os.urandom(16)  # 16-bajtowa sól
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + hash.hex()

def password_verify(password, stored_hash):
    salt, hash = stored_hash.split(':')
    salt = bytes.fromhex(salt)
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return new_hash.hex() == hash

stored_hash=password_hash('secret')
print('hash (secret): %s' % stored_hash)
print('Verify: %s' % password_verify('secret', stored_hash))
