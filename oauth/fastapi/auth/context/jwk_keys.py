# context.jwk_keys.py
from jwcrypto import jwk
from os import environ
from random import SystemRandom


class JwkContext():

    jwt_key = None
    rsa_key = None

    #  keys / config
    def random_token(self, length, byte_filter):
        allowed_bytes = ''.join(c for c in map(chr, range(128)) if byte_filter(c))
        random = SystemRandom()
        return ''.join([random.choice(allowed_bytes) for _ in range(length)])

    def alpha_numeric_string(self, length):
        return self.random_token(length, str.isalnum)

    def init_jwt_key(self):
        jwt_key_str = environ.get('JWT_KEY')
        if jwt_key_str:
            return jwk.JWK.from_json(jwt_key_str)
        else:
            jwt_key = jwk.JWK.generate(kty='oct', size=256, kid=self.alpha_numeric_string(16), use='sig', alg='HS256')
            # Zapisz klucz w bezpiecznym miejscu
            return jwt_key

    def init_rsa_key(self):
        rsa_key_str = environ.get('RSA_KEY')
        if rsa_key_str:
            return jwk.JWK.from_pem(rsa_key_str.encode())
        else:
            rsa_key = jwk.JWK.generate(kty='RSA', size=2054, kid=self.alpha_numeric_string(16), use='sig', alg='RS256')
            # Zapisz klucz w bezpiecznym miejscu
            return rsa_key

    def get_jwt_key(self):
        if not self.jwt_key:
            self.jwt_key = self.init_jwt_key()
        return self.jwt_key

    def get_rsa_key(self):
        if not self.rsa_key:
            self.rsa_key = self.init_rsa_key()
        return self.rsa_key
