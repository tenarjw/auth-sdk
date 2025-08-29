# oid_token.py
import json
import time
import logging
from typing import Dict

from jwcrypto import jwt
from jwcrypto.common import JWException
from sqlalchemy.ext.asyncio import AsyncSession

from jwcrypto.jws import JWS

try:
    import flask
except ImportError:
    flask = None

if flask:
    starlette = None
else:
    try:
        import starlette
    except ImportError:
        starlette = None

from .context import jwk_context, DataManager

if starlette is None:
    HTTP_401_UNAUTHORIZED = 401
    HTTP_403_FORBIDDEN = 403

    class HTTPException(JWException):
        def __init__(self, status_code, detail, headers):
            super(Exception, self).__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

else:
    from starlette.exceptions import HTTPException
    from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

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
    if key.key_type == 'oct':
        alg = 'HS256'
    else:
        alg = "RS256"
    try:
        token = jwt.JWT(
            header={'alg': alg, 'kid': key.kid},
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


def create_id_token(host_url, user_id, client_id, extra_claims):
    claims = {
        'iss': host_url,
        'sub': str(user_id),
        'aud': str(client_id),
        'iat': int(time.time()),
        'exp': int(time.time()) + ID_TOKEN_EXPIRY
    }
    claims.update(extra_claims)
    key = jwk_context.get_rsa_key()
    return jwt_encode(claims, key)


async def access_token_retrieve_or_create( dm : DataManager, app_id, user_id=0, scope='', host_url='', autorenew=True):
    tk = await dm.get_access_token(app_id, user_id)
    if tk:  # czy aktualny?
        key = jwk_context.get_rsa_key()
        try:
            jwt_decode(tk.token, key)
        except JWException:
            if autorenew:
                token = create_id_token(host_url, user_id, app_id, {'scope': scope})
                await dm.put_access_token(token, app_id, user_id)
        return tk.token
    else:
        token = create_id_token(host_url, user_id, app_id, {'scope': scope})
        await dm.put_access_token(token, app_id, user_id)
        return token


async def api_token_create(dm : DataManager, client_id, user_id, scope, session: AsyncSession):
    app_id = await dm.int_client_id(client_id, session)
    return await access_token_retrieve_or_create(app_id, user_id, scope)

def api_token_new(dm : DataManager, client_id, user_id, scope='', host_url=''):
    app_id = dm.int_client_id(client_id)
    token = create_id_token(host_url, user_id, app_id, {'scope': scope})
    dm.put_access_token(token, app_id, user_id)
    return token

def api_token_decode(access_token):
    key = jwk_context.get_rsa_key()
    try:
        payload = jwt_decode(access_token, key)
        if 'exp' in payload and payload['exp'] < int(time.time()):
            raise OAuthException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                type=OAuthException.INVALID_REQUEST
            )
    except JWException as e:
        raise OAuthException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate token: {str(e)}",
            type=OAuthException.INVALID_REQUEST
        )
    logger = logging.getLogger("collector")
    if not payload:
        raise OAuthException(
            'access_token owner',
            'invalid_request',
        )
    logger.info('Payload:')
    for k in payload:
        logger.info('%s : %s' % (k, payload[k]))
    scope_list = payload['scope'].split(',') if ('scope' in payload) and (payload['scope'] is not None) else []
    try:
        user_id = int(payload['sub'])
    except:
        user_id = payload['sub']
    try:
        client_id = int(payload['aud'])
    except:
        client_id = 0  # payload['aud']
    return (scope_list, user_id, client_id)


def api_token_to_owner(token, scopes, scope_str):
    logger = logging.getLogger("collector")
    logger.info('TOKEN_TOowner %s, %s, %s' % (token, scopes, scope_str))
    if scopes:
        authenticate_value = f'Bearer scope="{scope_str}"'
    else:
        authenticate_value = "Bearer"
    try:
        scope_list, user_ident, client_ident = api_token_decode(token)
        for scope in scopes:
            if scope not in scope_list:
                logger.info('scope not in list' + scope)
                raise OAuthException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not enough permissions (certificate) %s" % scope,
                    headers={"WWW-Authenticate": authenticate_value},
                    type=OAuthException.INVALID_SCOPES
                )
    except JWException as e:
        logger.error(f"JWT decoding error: {str(e)}")
        raise OAuthException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": authenticate_value},
            type=OAuthException.INTERNAL_ERROR
        )
    if (not user_ident) and (not client_ident):
        logger.info('must be user or client')
        raise OAuthException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid token.",
            headers={"WWW-Authenticate": authenticate_value},
            type=OAuthException.INVALID_CLIENT
        )
    else:
        return (client_ident, user_ident, scope_list)


def get_refresh_token_payload(refresh_token: str) -> Dict:
    """
    Dekoduje i weryfikuje refresh token, zwracając jego ładunek.
    """
    try:
        jws = JWS()
        jws.deserialize(refresh_token)
        # Załóżmy, że klucz do refresh tokena jest taki sam jak dla tokena dostępu
        jws.verify(jwk_context.get_rsa_key())
        return json.loads(jws.payload)
    except Exception as e:
        raise OAuthException(f"Invalid refresh token: {e}")