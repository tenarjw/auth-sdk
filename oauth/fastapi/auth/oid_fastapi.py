# oid_fastapi.py
from urllib import request

from fastapi import Depends, APIRouter, Query, Request, Form
from fastapi.responses import RedirectResponse
from typing import Optional, Dict
from urllib.parse import urlencode
from jwcrypto import jwk
from sqlalchemy.ext.asyncio import AsyncSession

from dependencies.db import get_db
from .context import DataManager, jwk_context
from .context.session_fastapi import get_session_uid
from .oid_token import api_token_create, api_token_decode, HTTPException, jwt_decode
from .oid_core import validator, OAuthException
from .oid_core import time_to_now, OAuth2RequestForm, LOGIN_TIMEOUT, \
    handle_oauth_authorize, handle_grant_type_authorization_code

from fastapi import HTTPException

from .oid_core import OAuth2RequestForm
from .oid_token import api_token_create, get_refresh_token_payload, OAuthException

from .oid_types import Introspection, ResponseType

router = APIRouter(
    prefix="",
    tags=['oauth'],
    #  dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)

@router.post("/token", response_model=None)
async def post_token(*,
                     form_data: OAuth2RequestForm = Depends(), \
                     db: AsyncSession = Depends(get_db),\
                     ) -> Dict:
    """
    Authorization code grant / Client Credentials
    """
    dm = DataManager(db)
    if form_data.grant_type == 'client_credentials':
        client = await dm.get_client_uuid(form_data.client_id)
        if not client:
            raise HTTPException(status_code=400, detail="Incorrect client id")
        if client.secret != form_data.client_secret:
            raise HTTPException(status_code=400, detail="Incorrect client/secret")
        try:
            access_token = api_token_create(client.uuid, 0, client.scopes)
            return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}
        except Exception as e:
            raise HTTPException(status_code=400, detail="Internal error: %s" % e)
    elif form_data.grant_type == 'authorization_code':
        if not form_data.code:
            raise OAuthException(
                'code param is missing',
                OAuthException.INVALID_REQUEST,
            )
        (client_id, redirect_uri, client_secret, code, scope) = await validator.check_grant_type_authorization_form(dm,form_data)
        # todo: host_url?
        return await handle_grant_type_authorization_code(dm,'',client_id, redirect_uri, code, scope, form_data)
    else:
        raise HTTPException(status_code=400, detail="Not implemented yet")

@router.get('/authorize', response_model=None)
async def get_authorize(
    request: Request = None,
    client_id: str = ...,
    redirect_uri: Optional[str] = Query(description="""Adres przekierowania po uwierzytelnieniu.
                                  Opcjonalny, ale gdy podajemy, musi to być jedno z zarejestrowanych adresów URL."""),
    response_type: ResponseType = Query(default=ResponseType.token, \
                                        description="""Typ odpowiedzi. 
                                                         W Authorization Code Grant musi być "code"."""),
    response_mode: Optional[str] = Query('fragment', \
                                         description="""Określa, czy parametry mają być dołączane do przekierowania w zapytaniu ("query"),
         czy jako fragment URL ("fragment") - po znaku #.
         Dla response_type=code wartością domyślną jest 'query' w p.p. - fragment.
         W tej implementacji parametr przyjmuje zawsze wartość domyślną (podana w zapytaniu jest ignorowana)."""),
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    code_challenge: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
    ):
    """
    #Authorisation
    """
    dm = DataManager(db)
    args = dict(request.query_params)
    (response_type, client_id, redirect_uri, scopes, state,
         response_mode, code_challenge, code_challenge_method) = validator.validate_oauth_params(dm,args)
    response_mode = validator.valid_response_mode(args.get('response_mode'), response_type)
    if response_type == 'code':  # authorization code grant
        #fast api / flask
        (user_id, auth_time) = get_session_uid(request)
        # In case user is not logged in, we redirect to the login page and come back
        # Also if they didn't authenticate recently enough
        if not user_id or time_to_now(auth_time) > LOGIN_TIMEOUT:
            raise OAuthException(
                'user is not logged in or login timeout',
                OAuthException.INVALID_REQUEST,
            )
    else:
        user_id = 0
    response_params = await handle_oauth_authorize(dm, response_type, user_id, client_id,
                                             redirect_uri, scopes, state,
                                             code_challenge=code_challenge, code_challenge_method=code_challenge_method)
    if 'error' in response_params:
        # If those are not valid, we must not redirect back to the client
        # - instead, we display a message to the user
        return response_params
    location = '{}{}{}'.format(
        redirect_uri,
        '?' if response_mode == 'query' else '#',
        urlencode(response_params)
    )
    return RedirectResponse(location, status_code=302)


@router.post('/introspect', response_model=Introspection)
async def post_introspect(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
    ) -> Introspection:
    """
    """
    try:
        dm = DataManager(db)
        scope_list, user_id, client_id = api_token_decode(token)
        payload = jwt_decode(token, jwk_context.get_rsa_key())
        base_url = str(request.base_url)
        return Introspection(
            active=True,
            client_id=client_id,
            username=await dm.ext_user_id(user_id) if user_id else None,
            scope=' '.join(scope_list),
            sub=str(user_id) if user_id else None,
            aud=client_id,
            iss=base_url,
            exp=payload.get('exp'),
            iat=payload.get('iat')
        )
    except OAuthException as e:
        return Introspection(active=False)


@router.get('/jwks', response_model=None)
def get_jwks_class() -> Dict:
    keyset = jwk.JWKSet()
    keyset.add(
        jwk_context.get_rsa_key()
    )
    # keyset.add(  jwk_context.get_jwt_key()   ) # public keynot exists
    return keyset.export(private_keys=False, as_dict=True)


@router.post('/revoke', response_model=None)
def post_revoke_class(
    token: str = ...,
    token_type_hint: Optional[str] = None
) -> None:
    """
    tools
    """
    raise HTTPException(status_code=400, detail="Not implemented yet")



@router.post("/refresh", response_model=None)
async def post_refresh(
    form_data: OAuth2RequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """
    Refresh Token Grant
    """
    dm = DataManager(db)

    if form_data.grant_type != 'refresh_token':
        raise HTTPException(
            status_code=400,
            detail="Invalid grant type. Expected 'refresh_token'."
        )

    if not form_data.refresh_token:
        raise HTTPException(
            status_code=400,
            detail="Missing 'refresh_token' parameter."
        )

    try:
        # Dekoduj refresh token, aby uzyskać dane użytkownika i klienta
        payload = get_refresh_token_payload(form_data.refresh_token)
        user_id = payload.get('sub')
        client_id_uuid = payload.get('aud')
        scopes = payload.get('scope')

        if not user_id or not client_id_uuid or not scopes:
            raise OAuthException("Invalid refresh token payload.")

        # Upewnij się, że klient wciąż istnieje i ma odpowiednie uprawnienia
        client = await dm.get_client_uuid(client_id_uuid)
        if not client:
            raise OAuthException("Client not found.")

        # Opcjonalnie: można dodać weryfikację, czy user_id jest wciąż aktywny

        # Wygeneruj nowy access token
        access_token = api_token_create(client_id_uuid, user_id, scopes)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600, # Czas ważności tokenu w sekundach
            # Opcjonalnie: wygeneruj nowy refresh token i unieważnij stary
            # "refresh_token": new_refresh_token
        }
    except OAuthException as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid refresh token: {e}"
        )
    except Exception as e:
        # Obsługa innych, nieoczekiwanych błędów
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {e}"
        )

#/.well-known/openid-configuration
@router.get('/.well-known/openid-configuration', response_model=None)
def get_config(request: Request) -> Dict:
    base_url = str(request.base_url)
    return {
        "issuer": base_url,
        "authorization_endpoint": base_url + "oauth",
        "token_endpoint": base_url + "oauth/token",
        "introspection_endpoint": base_url + "oauth/introspect",
        "userinfo_endpoint": base_url + "oauth/userinfo",
        "end_session_endpoint": base_url + "oauth/logout",
        "frontchannel_logout_session_supported": False,
        "frontchannel_logout_supported": True,
        "jwks_uri": base_url + "oauth/jwks",
        "grant_types_supported": [
            "authorization_code",
            "client_credentials"
        ],
        "response_types_supported": [
            "code",
            "none",
            "id_token",
            "token",
#            "id_token token",
            "code id_token",
            "code token",
#            "code id_token token"
        ]
    }
