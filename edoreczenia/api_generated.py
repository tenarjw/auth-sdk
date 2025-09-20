# api_generated.py

import requests
from requests import Response, Session
from typing import Optional, Dict, Any

# ----------------------------------------------------------------------
# Podstawowy klient API
# ----------------------------------------------------------------------

from requests import Response, Session
from typing import Optional, Dict, Any


class ApiClient:
  """
  - Używa jednej sesji dla wszystkich żądań (wydajność).
  - Automatycznie obsługuje błędy HTTP.
  - obsługuje ciało żądania w formacie JSON oraz z formularza.
  """

  def __init__(self, access_token: Optional[str] = None, test=False, base_url: str = 'https://edoreczenia.gov.pl'):
    self.access_token = access_token
    self.base_url = base_url
    self.session = Session()
    if test:
      self.token_url = 'https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect'
      self.api_url = 'https://int-ow.edoreczenia.gov.pl/auth/realms/EDOR/account'
      self.pp_url = 'https://uaapi-int-ow.poczta-polska.pl/api/v1'
      self.bae_url = 'https://int-ow.edoreczenia.gov.pl/api/se/v1'
      self.host = "https://int-ow.edoreczenia.gov.pl/"
    else:  # https://ow.edoreczenia.gov.pl
      self.token_url = 'https://ow.edoreczenia.gov.pl/auth/realms/EDOR/protocol/openid-connect'
      self.api_url = 'https://ow.edoreczenia.gov.pl/auth/realms/EDOR/account'
      self.pp_url = 'https://uaapi-ow.poczta-polska.pl/api/v3'
      self.bae_url = 'https://ow.edoreczenia.gov.pl/api/se/v3'
      self.host = "https://ow.edoreczenia.gov.pl/"
    if self.access_token:
      self.session.headers['Authorization'] = f'Bearer {self.access_token}'

  def call_api(
      self,
      method: str,
      path: str,
      path_params: Optional[Dict[str, Any]] = None,
      query_params: Optional[Dict[str, Any]] = None,
      header_params: Optional[Dict[str, Any]] = None,
      body: Optional[Any] = None,
      form_params: Optional[Dict[str, Any]] = None,
      full_url: Optional[Dict[str, Any]] = None,
      **kwargs
  ) -> Response:
    """
    Metoda do wykonywania rzeczywistych wywołań API.
    """
    # Sprawdzenie, czy nie użyto jednocześnie body i form_params
    if body is not None and form_params is not None:
      raise ValueError("Nie można jednocześnie używać parametrów 'body' i 'form_params'.")

    if not full_url:
      url=self.base_url
      if path.find('auth') == 0:
        url = self.host
      elif path.find('search') >= 0:
        url = self.bae_url
      elif path.find('/evidences/') >= 0:  # pobranie dowodów z PP nie działa - wykorzystanie beuis
        url = 'https://edoreczenia.gov.pl/api/beuis/v2'
      else:
        url = self.pp_url
      full_url = url.rstrip('/') + '/' + path.format(**(path_params or {})).lstrip('/')

    request_kwargs = {
      "method": method.upper(),
      "url": full_url,
      "params": query_params,
      "headers": header_params,
    }

    # Obsługa ciała żądania i danych z formularza
    if isinstance(body, dict):
      request_kwargs["json"] = body
    elif body is not None:
      request_kwargs["data"] = body
    elif form_params is not None:
      request_kwargs["data"] = form_params  # `requests` automatycznie zakoduje słownik jako form-urlencoded

    response = self.session.request(**request_kwargs)
    response.raise_for_status()

    return response

  def close_session(self):
    """Metoda do zamknięcia sesji, gdy klient nie jest już potrzebny."""
    self.session.close()

# ----------------------------------------------------------------------
# Krok 2: Wygenerowane klasy API na podstawie ua.json i se.json
# ----------------------------------------------------------------------

class MessagesApi:
  def __init__(self, api_client: ApiClient):
    self.api_client = api_client

  def getMessages(self, eDeliveryAddress: str, **kwargs) -> Any:
    """Pobranie listy wiadomości."""
    path = '/{eDeliveryAddress}/messages'
    path_params = {'eDeliveryAddress': eDeliveryAddress}
    return self.api_client.call_api('GET', path, path_params=path_params, query_params=kwargs)

  def postMessage(self, body: Dict[str, Any], eDeliveryAddress: str, **kwargs) -> Any:
    """Wysłanie wiadomości."""
    path = '/{eDeliveryAddress}/messages'
    path_params = {'eDeliveryAddress': eDeliveryAddress}
    return self.api_client.call_api('POST', path, path_params=path_params, body=body, **kwargs)

  def getMessage(self, eDeliveryAddress: str, messageId: str, **kwargs) -> Any:
    """Pobranie wiadomości o danym id."""
    path = '/{eDeliveryAddress}/messages/{messageId}'
    path_params = {'eDeliveryAddress': eDeliveryAddress, 'messageId': messageId}
    return self.api_client.call_api('GET', path, path_params=path_params, query_params=kwargs)

  def deleteMessage(self, eDeliveryAddress: str, messageId: str, **kwargs) -> Any:
    """Usunięcie wiadomości o podanym id."""
    path = '/{eDeliveryAddress}/messages/{messageId}'
    path_params = {'eDeliveryAddress': eDeliveryAddress, 'messageId': messageId}
    return self.api_client.call_api('DELETE', path, path_params=path_params, **kwargs)


class EvidencesApi:
  def __init__(self, api_client: ApiClient):
    self.api_client = api_client

  def getEvidencesForMessage(self, eDeliveryAddress: str, messageId: str, **kwargs) -> Any:
    """Pobranie potwierdzeń dla danej wiadomości."""
    path = '/{eDeliveryAddress}/messages/{messageId}/evidences'
    path_params = {'eDeliveryAddress': eDeliveryAddress, 'messageId': messageId}
    return self.api_client.call_api('GET', path, path_params=path_params, query_params=kwargs)

  def getZipEvidences(self, eDeliveryAddress: str, messageId: str, **kwargs) -> Any:
    """Pobranie pliku zip z technicznymi dowodami."""
    path = '/{eDeliveryAddress}/evidences/{messageId}/technical-evidences-file'
    path_params = {'eDeliveryAddress': eDeliveryAddress, 'messageId': messageId}
    return self.api_client.call_api('GET', path, path_params=path_params, **kwargs)

  def getEvidence(self, eDeliveryAddress: str, evidenceId: str, **kwargs) -> Any:
    """Pobranie potwierdzenia po jego ID."""
    # Uwaga: w ua.json są dwa endpointy do pobierania dowodu po ID.
    # Ten wybrano z uwagi na `edoreczenia.py`.
    path = '/{eDeliveryAddress}/messages/evidences/{evidenceId}'
    path_params = {'eDeliveryAddress': eDeliveryAddress, 'evidenceId': evidenceId}
    return self.api_client.call_api('GET', path, path_params=path_params, **kwargs)

class SubscriptionsApi:
  def __init__(self, api_client: ApiClient):
    self.api_client = api_client

  def putSubscriptions(self, eDeliveryAddress: str, body: Dict[str, Any], **kwargs) -> Any:
    """Tworzy lub aktualizuje subskrypcję."""
    path = '/{eDeliveryAddress}/message_subscriptions'
    path_params = {'eDeliveryAddress': eDeliveryAddress}
    return self.api_client.call_api('PUT', path, path_params=path_params, body=body, **kwargs)


class AttachmentsApi:
  def __init__(self, api_client: ApiClient):
    self.api_client = api_client

  def getMessageAttachment(self, eDeliveryAddress: str, messageId: str, attachmentId: str, **kwargs) -> Any:
    """Pobranie załącznika o podanym id."""
    path = '/{eDeliveryAddress}/messages/{messageId}/attachments/{attachmentId}'
    path_params = {
      'eDeliveryAddress': eDeliveryAddress,
      'messageId': messageId,
      'attachmentId': attachmentId
    }
    # Zgodnie z kodem `edoreczenia.py`, ta funkcja powinna zwracać krotkę (dane, kod, nagłówki)
    # To musi być obsłużone w `ApiClient.call_api`
    print("Warning: getMessageAttachment expects a tuple (data, code, headers) to be returned.")
    response = self.api_client.call_api('GET', path, path_params=path_params, **kwargs)
    # Symulacja zwracanej wartości
    return (response, 200, {})


class SearchEngineApi:
  def __init__(self, api_client: ApiClient):
    self.api_client = api_client

  def SearchBAE(self, client_cert_subject: str, body: Dict[str, Any], **kwargs) -> Any:
    """Wyszukiwanie BAE (zgodne z `se.json`)."""
    path = '/search/bae_search'
    header_params = {'ClientCert-Subject': client_cert_subject}
    return self.api_client.call_api('POST', path, header_params=header_params, body=body, **kwargs)

  def SearchBAE1(self, body: Dict[str, Any], **kwargs) -> Any:
    """Wyszukiwanie BAE (dla osób/instytucji)."""
    path = '/search/bae_search'
    return self.api_client.call_api('POST', path, body=body, **kwargs)

  def SearchBAE2(self, body: Dict[str, Any], **kwargs) -> Any:
    """Wyszukiwanie BAE (dla EDA)."""
    path = '/search/bae_search'
    return self.api_client.call_api('POST', path, body=body, **kwargs)