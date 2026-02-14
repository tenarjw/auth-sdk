# oid_token.py
from os import environ
import json
import time
from random import SystemRandom
from jwcrypto import jwt, jwk
from jwcrypto.common import JWException
from starlette.exceptions import HTTPException

RSA_KEY=None

def alpha_numeric_string(length):
    allowed_bytes = ''.join(c for c in map(chr, range(128)) if str.isalnum(c))
    random = SystemRandom()
    return ''.join([random.choice(allowed_bytes) for _ in range(length)])

class OAuthException(HTTPException):
    INVALID_REQUEST = 'invalid_request'
    INVALID_CLIENT = 'invalid_client'
    UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type'
    INVALID_GRANT = 'invalid_grant'
    UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type'
    INVALID_SCOPES = 'invalid_scopes'
    INVALID_CREDENTIALS = 'invalid_credentials'
    INTERNAL_ERROR = 'Internal_error'

    def __init__(self, *args, type=INVALID_CREDENTIALS, **kwargs):
        self.type = type
        super(OAuthException, self).__init__(*args, **kwargs)


def jwt_encode(claims, key):
    try:
        token = jwt.JWT(
            header={'alg': "RS256", 'kid': key.kid},
            claims=claims
        )
    except JWException as e:
        raise OAuthException(
            status_code=500,
            detail=f"Failed to encode JWT: {str(e)}",
            type=OAuthException.INTERNAL_ERROR
        )
    token.make_signed_token(key)
    return token.serialize()


def jwt_decode(serialized, key):
    token = jwt.JWT(jwt=serialized, key=key)
    return json.loads(token.claims)


ID_TOKEN_EXPIRY = 3600  # 1 godzina


def get_rsa_key():
    global RSA_KEY
    if RSA_KEY:
        return RSA_KEY
    rsa_key_str = environ.get('RSA_KEY')
    if rsa_key_str:
        RSA_KEY=jwk.JWK.from_pem(rsa_key_str.encode())
        return RSA_KEY
    else:
        RSA_KEY = jwk.JWK.generate(kty='RSA', size=2054, kid=alpha_numeric_string(16), use='sig', alg='RS256')
        # todo: utrwalenie klucza
        return RSA_KEY


def create_token(host_url, user_id, client_id, extra_claims):
    claims = {
        'iss': host_url,
        'sub': str(user_id),
        'aud': str(client_id),
        'iat': int(time.time()),
        'exp': int(time.time()) + ID_TOKEN_EXPIRY
    }
    claims.update(extra_claims)
    key = get_rsa_key()
    token=jwt_encode(claims, key)
    return token

