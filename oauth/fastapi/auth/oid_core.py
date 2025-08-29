# oid_core.py
import hashlib
from datetime import datetime
from fastapi.param_functions import Form
import time
import base64
from jwcrypto import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from jwcrypto.common import base64url_encode

from auth.context import jwk_context, db_context
from auth.oid_token import jwt_encode, jwt_decode, create_id_token, access_token_retrieve_or_create

def time_to_now(ts):
    return int(datetime.now().timestamp() - ts)

LOGIN_TIMEOUT = 24 * 60 * 60  # seconds

class OAuth2RequestForm:

    def __init__(
        self,
        grant_type: str = Form(default='client_credentials', regex="authorization_code|client_credentials", description="obowiązkowy"),
        code: str = Form(default=None, description="Kod uzyskany w zapytaniu /authorize - obowiązkowy dla authorization_code"),
        client_id: str = Form(default=None, description="Id programu (klienta) - przy client_credentials"),
        client_secret: str = Form(default=None, description="Sekret dla programu (klienta) - przy client_credentials"),
        scope: str = Form(default='', description="Opcjonalny. Zakresy informacji/funkcji dla klienta. Identyfikatory rozdzielone spacjami'"),
        redirect_uri: str = Form(default='', description="Jesli podany na etapie autoryzacji - obowiązkowy (taki sam)"),
        code_verifier: str = Form(default='', description='Obowiązkowy - o ile zapytanie o kod (authorization) zawierało "code_challenge"')
    ):
        self.grant_type = grant_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scope.split()
        self.redirect_uri = redirect_uri
        self.code = code
        self.code_verifier = code_verifier

    async def __call__(self, form):
        return self

def handle_oauth_authorize(host_url, session_sid, response_type, user_id, client_id, redirect_uri, scopes, state, code_challenge=None, code_challenge_method=None):
    try:
        cl_app = validator.validate_client(client_id)
        redirect_uri = validator.validate_redirect_uri(cl_app, redirect_uri)
    except OAuthException as e:
        return {
            'error': e.type,
            'error_description': str(e)
        }
    response_params = {}
    # state, if present, is just mirrored back to the client
    if state:
        response_params['state'] = state
    response_types = response_type.split()
    extra_claims = {
        'sid': session_sid,
    }
    if 'code' in response_types:
        # Generate code that can be used by the client server to retrieve
        # the token. It's set to be valid for 60 seconds only.
        # TODO: The spec says the code should be single-use. We're not enforcing
        # that here.
        payload = {
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'user_id': user_id,
            'scopes': scopes,
            'exp': int(time.time()) + 60,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method
        }
        payload.update(extra_claims)
        key = jwk_context.get_jwt_key()
        response_params['code'] = jwt_encode(payload, key)
    if 'token' in response_types:
        access_token = access_token_retrieve_or_create(client_id, user_id, scopes)
        response_params['access_token'] = access_token
        response_params['token_type'] = 'bearer'

        # at_hash - część id_token (OpenID) która  może być użyta do walidacji access_tokena
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(access_token.encode('ascii'))
        at_hash = base64url_encode(digest.finalize()[:16])
        extra_claims['at_hash'] = at_hash
    if 'id_token' in response_types:
        response_params['id_token'] = create_id_token(host_url, user_id, client_id, extra_claims)
    return response_params


def handle_grant_type_authorization_code(host_url, client_id, redirect_uri, code, scope, form_data):
    cl_app = validator.validate_client(client_id)
    redirect_uri = validator.validate_redirect_uri(cl_app, redirect_uri)
    if not code:
        raise OAuthException(
            'code param is missing',
            OAuthException.INVALID_GRANT,
        )
    key = jwk_context.get_jwt_key()
    try:
        payload = jwt_decode(code, key)
    except jwt.JWTExpired:
        raise OAuthException(
            'Code expired',
            OAuthException.INVALID_GRANT,
        )
    except ValueError:
        raise OAuthException(
            'code malformed',
            OAuthException.INVALID_GRANT,
        )
    if payload['client_id'] != cl_app.id:
        raise OAuthException(
            'client_id doesn\'t match the authorization request',
            OAuthException.INVALID_GRANT,
        )
    if payload['redirect_uri'] != redirect_uri:
        raise OAuthException(
            'redirect_uri doesn\'t match the authorization request',
            OAuthException.INVALID_GRANT,
        )
    if 'code_challenge' in payload and form_data.code_verifier:
        if not validator.validate_pkce(form_data.code_verifier, payload['code_challenge'], payload.get('code_challenge_method', 'S256')):
            raise OAuthException(
                'Invalid code verifier',
                OAuthException.INVALID_GRANT
            )

    # Retrieve/generate access token. We currently only store one per user/cl_app
    token = access_token_retrieve_or_create(
        cl_app.id,
        payload['user_id'],
        scope
    )
    response = {
        'access_token': token,
        'token_type': 'bearer'
    }
    if 'openid' in payload['scopes']:
        extra_claims = {name: payload[name] for name in payload if name in ['sid', 'nonce']}
    if scope:
        extra_claims['scope'] = scope
        response['id_token'] = create_id_token(host_url, payload['user_id'], cl_app.id, extra_claims)
    return response


def handle_grant_type_client_credentials(client_id, client_secret, scope):
    cl_app = validator.validate_client(client_id)
    validator.validate_client_secret(cl_app, client_secret)
    # Could be replaced with data migration
    if not cl_app.system_user_id:
        raise OAuthException(
            'not implemented yet',
            OAuthException.INVALID_REQUEST
        )
    token = access_token_retrieve_or_create(cl_app.id, scope=scope)
    return {
        'access_token': token,
        'token_type': 'bearer'
    }


RESPONSE_TYPES_SUPPORTED = [
    'code',
    'token',
#    'id_token token',
    'id_token'
]


class OAuthException(Exception):
    INVALID_REQUEST = 'invalid_request'
    INVALID_CLIENT = 'invalid_client'
    UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type'
    INVALID_GRANT = 'invalid_grant'
    UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type'

    def __init__(self, message, type):
        super(Exception, self).__init__(message)
        self.type = type


class OAuthValidator():

    def valid_response_type(self, response_type):
        if response_type not in RESPONSE_TYPES_SUPPORTED:
            raise OAuthException(
                'The only supported response_types are: {}'.format(', '.join(RESPONSE_TYPES_SUPPORTED)),
                OAuthException.UNSUPPORTED_RESPONSE_TYPE,
            )
        return response_type

    def validate_client(self, client_id):
        cl_app = db_context.get_client(int(client_id))
        if not cl_app:
            raise OAuthException(
                'client_id param is invalid',
                OAuthException.INVALID_CLIENT,
            )
        return cl_app

    def validate_redirect_uri(self, cl_app, redirect_uri):
        if cl_app.auth_redirect_uri != redirect_uri:
            raise OAuthException(
                'redirect_uri param doesn\'t match the pre-configured redirect URI',
                OAuthException.INVALID_GRANT,
            )
        return redirect_uri

    def validate_client_secret(self, cl_app, client_secret):
        if (not client_secret) or client_secret != cl_app.secret:
            raise OAuthException(
                'client_secret param is not valid',
                OAuthException.INVALID_CLIENT,
            )

    def valid_response_mode(self, response_mode, response_type):
        if not response_mode:
            return 'query' if response_type == 'code' else 'fragment'
        elif response_mode not in ['query', 'fragment']:
            raise OAuthException(
                'The only supported response_modes are \'query\' and \'fragment\'',
                OAuthException.INVALID_REQUEST
            )
        return response_mode

    def arg_or_null(self, args, id):
        return args[id] if id in args else None

    def validate_oauth_params(self, args):
        required_params = ['response_type', 'client_id', 'redirect_uri']
        for param in required_params:
            if param not in args or not args[param]:
                raise OAuthException(f"Missing required parameter: {param}", "invalid_request")

        if args['response_type'] not in RESPONSE_TYPES_SUPPORTED:
            raise OAuthException("Unsupported response type", "unsupported_response_type")

        # Walidacja redirect_uri
        if not args['redirect_uri'].startswith(app.auth_redirect_uri):
            raise OAuthException("Invalid redirect URI", "invalid_request")

        # Walidacja scope
        #if 'scope' in args and not validate_scopes(args['scope']):
        #  raise OAuthException("Invalid scope", "invalid_scope")

        # Dodatkowa walidacja nonce/state dla CSRF
        if 'nonce' in args and len(args['nonce']) < 8:
            raise OAuthException("Invalid nonce", "invalid_request")

        response_type = self.valid_response_type(args['response_type'])
        if 'client_id' not in args:
            raise OAuthException(
                'client_id param is missing',
                OAuthException.INVALID_CLIENT,
            )
        client_id = db_context.int_client_id(args['client_id'])
        if 'redirect_uri' not in args:
            raise OAuthException(
                'redirect_uri param is missing',
                OAuthException.INVALID_GRANT,
            )
        redirect_uri = args['redirect_uri']
        scopes = args.get('scope').split(' ') if args.get('scope') else []
        response_mode = args.get('response_mode')
        if not response_mode:
            response_mode = 'query' if response_type == 'code' else 'fragment'
        return (response_type,
                client_id,
                redirect_uri,
                scopes,
                self.arg_or_null(args, 'state'),
                response_mode,
                self.arg_or_null(args, 'code_challenge'),
                self.arg_or_null(args, 'code_challenge_method')
                )

    def validate_pkce(self, code_verifier, code_challenge, method='S256'):
        if not code_verifier or not code_challenge:
            raise OAuthException("PKCE parameters required", "invalid_request")

        if method == 'S256':
            # Oblicz challenge z verifier
            digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
            calculated_challenge = base64.urlsafe_b64encode(digest).decode('ascii').replace('=', '')
            return calculated_challenge == code_challenge
        elif method == 'plain':
            return code_verifier == code_challenge
        else:
            raise OAuthException("Unsupported code challenge method", "invalid_request")

    def check_grant_type_authorization_args(self, args):
        if 'client_id' not in args:
            raise OAuthException(
                'client_id param is missing',
                OAuthException.INVALID_CLIENT,
            )
        return (
            db_context.int_client_id(args['client_id']),
            args['redirect_uri'],
            self.arg_or_null(args, 'client_secret'),
            self.arg_or_null(args, 'code'),
            self.arg_or_null(args, 'scope')
        )

    def check_grant_type_authorization_form(self, form):
        if not form.client_id:
            raise OAuthException(
                'client_id param is missing',
                OAuthException.INVALID_CLIENT,
            )
        return (
            db_context.int_client_id(form.client_id),
            form.redirect_uri,
            form.client_secret,
            form.code,
            form.scope
        )

    def check_grant_type_client_args(self, args):
        if 'client_id' not in args:
            raise OAuthException(
                'client_id param is missing',
                OAuthException.INVALID_CLIENT,
            )
        return (
            db_context.int_client_id(args['client_id']),
            args['client_secret'],
            self.arg_or_null(args, 'scope')
        )

    def check_openid_authorize_args(self, args):
        if 'scope' not in args or args['scope'] != 'openid':
            raise OAuthException(
                'scope must be openid',
                OAuthException.INVALID_REQUEST,
            )
        response_type = self.valid_response_type(args['response_type'])
        if 'client_id' not in args:
            raise OAuthException(
                'client_id param is missing',
                OAuthException.INVALID_CLIENT,
            )
        client_id = db_context.int_client_id(args['client_id'])
        if 'redirect_uri' not in args:
            raise OAuthException(
                'redirect_uri param is missing',
                OAuthException.INVALID_GRANT,
            )
        max_age = int(args['max_age']) if ('max_age' in args and args['max_age']) else 0

        return (response_type,
                client_id,
                self.arg_or_null(args, 'redirect_uri'),
                self.arg_or_null(args, 'state'),
                self.arg_or_null(args, 'response_mode'),
                self.arg_or_null(args, 'nonce'),
                self.arg_or_null(args, 'display'),
                self.arg_or_null(args, 'prompt'),
                max_age,
                self.arg_or_null(args, 'ui_locales'),
                self.arg_or_null(args, 'id_token_hint'),
                self.arg_or_null(args, 'login_hint'),
                self.arg_or_null(args, 'acr_values')
                )


validator = OAuthValidator()

