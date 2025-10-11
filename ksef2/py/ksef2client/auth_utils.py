import hashlib
import base64
from typing import Optional
from .client import KSeFClient
from .models import (
  AuthenticationChallengeResponse,
  AuthenticationInitResponse,
  AuthenticationTokensResponse,
  AuthenticationTokenRefreshResponse,
  AuthenticationOperationStatusResponse,
  InitTokenAuthenticationRequest,
  AuthenticationContextIdentifier,
  AuthenticationContextIdentifierType,
  AuthorizationPolicy,
  TokenAuthorIdentifierTypeIdentifier,
  TokenAuthorIdentifierType,
  TokenContextIdentifierTypeIdentifier,
  TokenContextIdentifierType,
  GenerateTokenRequest,
  GenerateTokenResponse,
  TokenPermissionType
)
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def ksef2_challenge(ksef_client : KSeFClient) -> AuthenticationChallengeResponse:
  """Pobranie wyzwania w KSeF 2.0"""
  return ksef_client.challenge()

def ksef2_init_signed_auth(ksef_client, context_identifier: dict, signed_xml: bytes) -> AuthenticationInitResponse:
  """Inicjowanie uwierzytelniania podpisem kwalifikowanym w KSeF 2.0"""

  # Konwersja identyfikatora kontekstu
  context_id = AuthenticationContextIdentifier(
    type=AuthenticationContextIdentifierType(context_identifier["type"]),
    value=context_identifier["value"]
  )

  # Przygotowanie requestu - BEZ CHALLENGE!
  auth_request = InitTokenAuthenticationRequest(
    challenge="",  # Puste dla podpisu kwalifikowanego
    contextIdentifier=context_id,
    encryptedToken=base64.b64encode(signed_xml).decode('ascii')
  )

  return ksef_client.init_signed(auth_request)  # Teraz używa poprawnego endpointu

def ksef2_init_token_auth(
    ksef_client,
    context_identifier: dict,
    ksef_token: str,
    allowed_ips: Optional[list] = None
) -> AuthenticationInitResponse:
  """Inicjowanie uwierzytelniania tokenem KSeF w KSeF 2.0"""

  # Pobierz challenge
  challenge_response = ksef2_challenge(ksef_client)

  # Przygotuj politykę autoryzacji (jeśli podano IP)
  authorization_policy = None
  if allowed_ips:
    from models import AllowedIps
    authorization_policy = AuthorizationPolicy(
      allowedIps=AllowedIps(ip4Addresses=allowed_ips)
    )

  # Przygotuj token z timestampem i zaszyfruj
  token_with_timestamp = f"{ksef_token}|{challenge_response.timestamp.isoformat()}"
  encrypted_token = encrypt_ksef_token2(token_with_timestamp)

  # Konwersja identyfikatora kontekstu
  context_id = AuthenticationContextIdentifier(
    type=AuthenticationContextIdentifierType(context_identifier["type"]),
    value=context_identifier["value"]
  )

  # Przygotowanie requestu
  auth_request = InitTokenAuthenticationRequest(
    challenge=challenge_response.challenge,
    contextIdentifier=context_id,
    encryptedToken=encrypted_token,
    authorizationPolicy=authorization_policy
  )

  return ksef_client.init_signed(auth_request)


def encrypt_ksef_token2(token_data: str, public_key_pem: str = None) -> str:
  """Szyfrowanie tokena KSeF RSA-OAEP-SHA256 w KSeF 2.0"""

  # Jeśli nie podano klucza, użyj domyślnego klucza MF
  if public_key_pem is None:
    public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwg...
... (klucz publiczny MF do szyfrowania tokenów)
-----END PUBLIC KEY-----"""

  public_key = RSA.import_key(public_key_pem)
  cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=hashlib.sha256)
  encrypted_data = cipher_rsa.encrypt(token_data.encode('utf-8'))

  return base64.b64encode(encrypted_data).decode('ascii')


def ksef2_redeem_tokens(ksef_client, reference_number: str) -> AuthenticationTokensResponse:
  """Wykupienie tokenów dostępu po udanym uwierzytelnieniu"""

  # Sprawdź status uwierzytelnienia
  status = ksef_client.status(reference_number)

  if status.status.code == 200:  # Sukces
    return ksef_client.token_redeem()
  else:
    raise Exception(f"Uwierzytelnienie nie powiodło się: {status.status.code} - {status.status.description}")


def ksef2_refresh_token(ksef_client) -> AuthenticationTokenRefreshResponse:
  """Odświeżenie tokena dostępu w KSeF 2.0"""
  return ksef_client.refresh_token()


def ksef2_revoke_token(ksef_client):
  """Unieważnienie tokena w KSeF 2.0"""
  ksef_client.revoke_token()


def ksef2_get_auth_status(ksef_client, reference_number: str) -> AuthenticationOperationStatusResponse:
  """Sprawdzanie statusu uwierzytelnienia w KSeF 2.0"""
  return ksef_client.status(reference_number)


def ksef2_list_authentications(ksef_client, page_size: int = 20) -> list:
  """Lista sesji uwierzytelniania w KSeF 2.0"""
  response = ksef_client.list_authentications(page_size=page_size)
  return response.items


def create_auth_request_xml2(challenge: str, identifier_type: str, identifier_value: str) -> bytes:
  """Tworzenie XML żądania uwierzytelnienia dla KSeF 2.0"""
  if identifier_type=='Nip':
    auth_xml=f"""<?xml version="1.0" encoding="utf-8"?>
<AuthTokenRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://ksef.mf.gov.pl/auth/token/2.0">
    <Challenge>{challenge}</Challenge>
    <ContextIdentifier>
        <Nip>{identifier_value}</Nip>
    </ContextIdentifier>
    <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>
</AuthTokenRequest>"""
  else:
    raise Exception('Niobsługiwany identyfikator')
  return auth_xml.encode('utf-8')