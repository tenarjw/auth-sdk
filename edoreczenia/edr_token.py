import uuid
from datetime import datetime
# https://pypi.org/project/jwt/
# pip uninstall jwt / pip install pyjwt

try:
  from jwt import (
    JWT,
    #  jwk_from_dict,
    jwk_from_pem,
  )
  ns_pyjwt=False
except:
  ns_pyjwt = True
  import jwt
import json
from  api_generated import ApiClient

def request_token(ADRES_ADE, NAZWA_SYSTEMU, key):
  header = {
    'alg': 'RS256',
    #"typ":"JWT"
  }
  #now=int(dt.now().timestamp())
  now=int(datetime.utcnow().timestamp())
  """
   Expected audiences are any of [
   https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR, 
   https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect/token, 
   https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect/ext/par/request, 
   https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect/ext/ciba/auth
   ]
  """
  payload = { #  token RFC7523
    #"aud": "https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect/token",
    "aud": "https://ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect/token",
    "exp": now+60000, # expiration time
    "iat": now, # issued at
    "iss": ADRES_ADE+'.SYSTEM.'+NAZWA_SYSTEMU,
    "jti": str(uuid.uuid4()), # JWT ID: unique identifier for the token.
    "nbf": now,
    "sub": ADRES_ADE+'.SYSTEM.'+NAZWA_SYSTEMU
  }
  if ns_pyjwt:
    token = jwt.encode(
        payload,
        key,
        algorithm='RS256',
        headers=header,
        json_encoder=None,
#        sort_headers=False
    )
  else:
    if isinstance(key, str):
      key = key.encode('utf-8')
    private_key = jwk_from_pem(key)
    instance = JWT()
    token = instance.encode(payload=payload, optional_headers=header, key=private_key, alg='RS256')
  # print(token)
  # sprawdź na https://jwt.io/
  return token

def post_auth_request(signed_token, ADE_ADRES):
  """
  Zapytanie:
    POST /auth/realms/EDOR/protocol/openid-connect/token?login_hint=$ADRES_ADE HTTP/1.1
    Connection: close
    User-Agent: PostmanRuntime/7.28.4
    Accept: */*
    Host: int-ow.edoreczenia.gov.pl
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 830

    client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&grant_type=client_credentials&client_assertion=$TOKEN

    gdzie:
        • $ADRES_ADE ‒ adres do e-Doręczeń, np. ADE.AE:PL-97075-47631-STVJH-19 ,
        • $TOKEN ‒ token JWS przygotowany i podpisany w poprzednich krokach, np.:

  """
  token_url='auth/realms/EDOR/protocol/openid-connect/token?login_hint='+ADE_ADRES
  header_params={
   'Content-Type': 'application/x-www-form-urlencoded',
   'Accept': '*/*',
   #'Host': 'int-ow.edoreczenia.gov.pl',
    'Host': 'ow.edoreczenia.gov.pl',
   'Accept-Encoding': 'gzip, deflate, br'
  }
  # Authentication setting
  # https://datatracker.ietf.org/doc/html/rfc7523#page-10
  form_params={
    'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'grant_type':'client_credentials',
    'client_assertion': signed_token
  }
  params = locals()
  collection_formats = {}
  path_params = {}
  query_params = {} #{'login_hint':ADE_ADRES}
  local_var_files = {}
  body_params = None
  api_client = ApiClient(None)
  response=api_client.call_api(
    'POST',
    token_url, # path
    path_params,
    query_params,
    header_params,
    body=body_params,
    form_params=form_params,
    #full_url=token_url
    #response_type=dict
  )
  return  (json.loads(response.text), response.status_code, response.headers)
