#!/usr/bin/python
# -*- coding: utf-8 -*-
import hashlib

def password_hash(password):
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'', 100000)  # w tym przykładzie nie używamy soli - stąd pusty bajt jako sól
    # takie rozwiązanie obniża bezpieczeństwo i jest przeznaczone tylko do demonstracji.
    return hash.hex()

def password_verify(password, stored_hash):
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'', 100000)
    return new_hash.hex() == stored_hash

stored_hash = password_hash('secret')
print('hash (secret): %s' % stored_hash)
print('Verify: %s' % password_verify('secret', stored_hash))
