from passlib.hash import md5_crypt

def password_hash2(password):
   return md5_crypt.hash(password, salt_size=8)

h2=password_hash2('secret')
print('Hash MD5: %s' % h2)
print('Verify: %s' % md5_crypt.verify('secret', h2))
