# client.py
# https://ksef-test.mf.gov.pl/docs/v2/openapi.json

import requests
from .models import *


class KSeFClient:
  def __init__(self, base_url: str = "https://ksef-test.mf.gov.pl"):
    self.base_url = base_url
    self.session = requests.Session()
    self.access_token = None

  def _get_headers(self, additional_headers: dict = None) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if self.access_token:
      headers["Authorization"] = f"Bearer {self.access_token}"
    if additional_headers:
      headers.update(additional_headers)
    return headers

  def set_access_token(self, token: str):
    self.access_token = token
    self.session.headers.update({"Authorization": f"Bearer {self.access_token}"})

  # --- UWIERZYTELNIANIE ---

  def challenge(self) -> AuthenticationChallengeResponse:
    # Generuje challenge do uwierzytelniania (metodą POST).
    response = self.session.post(
#      f"{self.base_url}/api/v2/auth/challenge", # zmiana API
      f"{self.base_url}/v2/auth/challenge",
      headers=self._get_headers()
    )
    response.raise_for_status()
    return AuthenticationChallengeResponse(**response.json())

  def auth_by_xades_signature(self, signed_xml: bytes) -> AuthenticationInitResponse:
    # Inicjuje uwierzytelnianie podpisem XAdES.
    headers = self._get_headers({"Content-Type": "application/xml", "Accept": "application/json"})
    response = self.session.post(
      f"{self.base_url}/v2/auth/xades-signature", # zmiana api
      data=signed_xml,
      headers=headers
    )
    response.raise_for_status()
    return AuthenticationInitResponse(**response.json())

  def auth_by_ksef_token(self, request: InitTokenAuthenticationRequest) -> AuthenticationInitResponse:
    # Inicjuje uwierzytelnianie tokenem KSeF.
    response = self.session.post(
      f"{self.base_url}/v2/auth/ksef-token", # zmiana API
      json=request.model_dump(by_alias=True),
      headers=self._get_headers()
    )
    response.raise_for_status()
    return AuthenticationInitResponse(**response.json())

  def auth_status(self, reference_number: str, auth_token : str) -> AuthenticationOperationStatusResponse:
    # Sprawdza status operacji uwierzytelniania.
    # Wymaga 'AuthenticationToken' jako Bearer
    auth_token_headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {auth_token}'}
    response = self.session.get(
      f"{self.base_url}/v2/auth/{reference_number}", # zmiana API
      headers=auth_token_headers
    )
    response.raise_for_status()
    return AuthenticationOperationStatusResponse(**response.json())

  def redeem_token(self, auth_token: str) -> AuthenticationTokensResponse:
    # Wykupuje tokeny dostępowe (AccessToken i RefreshToken).
    # Wymaga 'AuthenticationToken' jako Bearer
    headers = {"Authorization": f"Bearer {auth_token}", "Accept": "application/json"}
    response = self.session.post(
      f"{self.base_url}/v2/auth/token/redeem", # zmiana api
      headers=headers
    )
    response.raise_for_status()
    return AuthenticationTokensResponse(**response.json())

  def refresh_token(self, refresh_token: str) -> AuthenticationTokenRefreshResponse:
    # Odświeża AccessToken używając RefreshToken.
    headers = {"Authorization": f"Bearer {refresh_token}", "Accept": "application/json"}
    response = self.session.post(
      f"{self.base_url}/v2/auth/token/refresh",
      headers=headers
    )
    response.raise_for_status()
    return AuthenticationTokenRefreshResponse(**response.json())

  def revoke_current_session(self):
    # Unieważnia bieżącą sesję uwierzytelniania.
    response = self.session.delete(
      f"{self.base_url}/v2/auth/sessions/current",
      headers=self._get_headers()
    )
    response.raise_for_status()

  def list_authentications(self, page_size: int = 10, x_continuation_token: str = None) -> AuthenticationListResponse:
    # Pobiera listę aktywnych sesji uwierzytelniania.
    params = {"pageSize": page_size}
    headers = self._get_headers()
    if x_continuation_token:
      headers["x-continuation-token"] = x_continuation_token

    response = self.session.get(
      f"{self.base_url}/v2/auth/sessions",
      params=params,
      headers=headers
    )
    response.raise_for_status()
    return AuthenticationListResponse(**response.json())

  # --- SESJE ---

  def online_session_open(self, request: OpenOnlineSessionRequest) -> OpenOnlineSessionResponse:
    # Otwiera sesję interaktywną.
    payload=request.model_dump(by_alias=True)
    response = self.session.post(
      f"{self.base_url}/v2/sessions/online",
      json=payload,
      headers=self._get_headers()
    )
    response.raise_for_status()
    return OpenOnlineSessionResponse(**response.json())

  def online_session_send_invoice(self, reference_number: str, request: SendInvoiceRequest) -> SendInvoiceResponse:
    # Wysyła fakturę w sesji interaktywnej.
    response = self.session.post(
      f"{self.base_url}/v2/sessions/online/{reference_number}/invoices",
      json=request.model_dump(by_alias=True),
      headers=self._get_headers()
    )
    response.raise_for_status()
    return SendInvoiceResponse(**response.json())

  def online_session_terminate(self, reference_number: str):
    # Zamyka sesję interaktywną.
    response = self.session.post(
      f"{self.base_url}/v2/sessions/online/{reference_number}/close",
      headers=self._get_headers()
    )
    response.raise_for_status()
    # Zwraca 204 No Content, więc nie ma ciała odpowiedzi do sparsowania

  def batch_session_open(self, request: OpenBatchSessionRequest) -> OpenBatchSessionResponse:
    # Otwiera sesję wsadową.
    response = self.session.post(
      f"{self.base_url}/v2/sessions/batch",
      json=request.model_dump(by_alias=True),
      headers=self._get_headers()
    )
    response.raise_for_status()
    return OpenBatchSessionResponse(**response.json())

  def get_session_status(self, reference_number: str) -> SessionStatusResponse:
    # Pobiera status sesji (online lub batch).
    # POPRAWKA: Ujednolicony endpoint /sessions/{referenceNumber}
    response = self.session.get(
      f"{self.base_url}/v2/sessions/{reference_number}",
      headers=self._get_headers()
    )
    response.raise_for_status()
    return SessionStatusResponse(**response.json())

  def get_session_invoices(self, reference_number: str, page_size: int = 10,
                           x_continuation_token: str = None) -> SessionInvoicesResponse:
    # Pobiera listę faktur w sesji (online lub batch).
    params = {"pageSize": page_size}
    headers = self._get_headers()
    if x_continuation_token:
      headers["x-continuation-token"] = x_continuation_token

    response = self.session.get(
      f"{self.base_url}/v2/sessions/{reference_number}/invoices",
      params=params,
      headers=headers
    )
    response.raise_for_status()
    return SessionInvoicesResponse(**response.json())

  # --- FAKTURY  ---

  def query_invoices_metadata(self, request: InvoiceQueryFilters, page_size: int = 10,
                              page_offset: int = 0) -> QueryInvoicesMetadataResponse:
    # Wyszukuje metadane faktur.
    params = {"pageSize": page_size, "pageOffset": page_offset}
    response = self.session.post(
      f"{self.base_url}/v2/invoices/query/metadata",
      json=request.model_dump(by_alias=True, exclude_none=True),
      params=params,
      headers=self._get_headers()
    )
    response.raise_for_status()
    return QueryInvoicesMetadataResponse(**response.json())

  # --- TOKENY KSeF   ---

  def generate_token(self, request: GenerateTokenRequest) -> GenerateTokenResponse:
    # Generuje nowy token KSeF.
    response = self.session.post(
      f"{self.base_url}/v2/tokens",
      json=request.model_dump(by_alias=True, exclude_none=True),
      headers=self._get_headers()
    )
    response.raise_for_status()
    return GenerateTokenResponse(**response.json())

  def get_token_status(self, reference_number: str) -> TokenStatusResponse:
    # Pobiera status tokena KSeF.
    response = self.session.get(
      f"{self.base_url}/v2/tokens/{reference_number}",
      headers=self._get_headers()
    )
    response.raise_for_status()
    return TokenStatusResponse(**response.json())

  def revoke_token_by_ref(self, reference_number: str):
    # Unieważnia token KSeF.
    response = self.session.delete(
      f"{self.base_url}/v2/tokens/{reference_number}",
      headers=self._get_headers()
    )
    response.raise_for_status()
    # Zwraca 204 No Content

  # --- KLUCZE PUBLICZNE ---

  def get_public_keys(self) -> List[PublicKeyCertificate]:
    # Pobiera certyfikaty kluczy publicznych KSeF.
    # Ta operacja nie wymaga uwierzytelnienia
    headers = {"Accept": "application/json"}
    response = self.session.get(
      f"{self.base_url}/v2/security/public-key-certificates",
      headers=headers
    )
    response.raise_for_status()
    # Odpowiedź to lista, a nie obiekt, więc trzeba ją odpowiednio zmapować
    return [PublicKeyCertificate(**item) for item in response.json()]

