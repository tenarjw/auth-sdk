# lib/saml_utils.py
import base64
import binascii
import uuid
import datetime
import random
import string
import struct

import xmlsec
#from xml.etree.ElementTree import fromstring  # Do prostego parsowania XML, defusedxml.lxml jest lepsze dla bezpieczeństwa
from defusedxml.lxml import fromstring
from lxml import etree  # Lepiej użyć defusedxml.lxml dla bezpieczeństwa

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_der_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#from cryptography.hazmat.principles import hashes

import httpx  # Zmieniono z fastapi.requests na httpx
#from fastapi.logger import logger

from schemas.wk_schemas import WKUser
from .saml_decrypt import decrypt_saml_assertion_manual
from .xml_render import XMLRenderer
from .xml_sign import add_sign, add_sign_p12  # Zapewnij, że to jest poprawna ścieżka do add_sign (np. lib.xml_sign)
from core.config import settings

import asyncio
from typing import Callable, Any

import logging
logger = logging.getLogger(__name__)

namespaces = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/'
}

###### saml signature


def verify_saml_signatures(root):
  """
  Weryfikuje podpisy cyfrowe w odpowiedzi SAML/SOAP z Węzła Krajowego.
  Funkcja szuka wszystkich węzłów <ds:Signature>, pobiera z nich certyfikat X509
  i weryfikuje poprawność podpisu kryptograficznego.
  """

  # Definicja przestrzeni nazw występujących w pliku odp.xml
  namespaces = {
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
  }

  # Znajdź wszystkie podpisy w dokumencie
  signatures = root.xpath('//ds:Signature', namespaces=namespaces)
  if not signatures:
    print("Nie znaleziono żadnych podpisów w dokumencie.")
    return False

  print(f"Znaleziono {len(signatures)} podpis(y/ów). Rozpoczynam weryfikację...\n")

  # Rejestracja atrybutów "ID".
  # Musimy powiedzieć bibliotece xmlsec, że atrybut o nazwie "ID"
  # służy do identyfikacji węzłów (jest celem dla Reference URI).
  # Szukamy wszystkich elementów, które mogą być podpisane i wskazujemy ich atrybut ID.
  # W Twoim XML są to ArtifactResponse oraz Response.
  xmlsec.tree.add_ids(root, ["ID"])

  all_signatures_valid = True

  for i, signature_node in enumerate(signatures):
    print(f"--- Weryfikacja podpisu #{i + 1} ---")

    x509_cert_node = signature_node.find('.//ds:X509Certificate', namespaces=namespaces)
    if x509_cert_node is None:
      continue

    cert_pem = f"-----BEGIN CERTIFICATE-----\n{x509_cert_node.text.strip()}\n-----END CERTIFICATE-----"

    try:
      ctx = xmlsec.SignatureContext()
      key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM, None)
      ctx.key = key

      # Tutaj xmlsec szuka węzła, którego ID pasuje do Reference URI w podpisie.
      # Dzięki [POPRAWKA 2] teraz go znajdzie.
      ctx.verify(signature_node)

      print(f"Podpis #{i + 1}: PRAWIDŁOWY")

    except xmlsec.Error as e:
      # Błąd (1, 'failed to verify') zazwyczaj oznacza:
      # "Nie znalazłem węzła wskazanego w Reference URI"
      print(f"Podpis #{i + 1}: NIEPRAWIDŁOWY. Błąd: {str(e)}")
      all_signatures_valid = False
    except Exception as e:
      print(f"Podpis #{i + 1}: Błąd: {str(e)}")
      all_signatures_valid = False

  return all_signatures_valid


### odszyfrowanie
def analyze_encryption_structure(root):
  """Szczegółowa analiza struktury szyfrowania"""
  namespaces = {
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
    'xenc11': 'http://www.w3.org/2009/xmlenc11#',
    'dsig11': 'http://www.w3.org/2009/xmlenc11#',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
  }

  # Znajdź EncryptedAssertion
  encrypted_assertion = root.find(".//saml2:EncryptedAssertion", namespaces)
  if encrypted_assertion is None:
    print("Nie znaleziono EncryptedAssertion")
    return

  print("=== STRUKTURA SZYFROWANIA ===")

  # EncryptedData
  enc_data = encrypted_assertion.find(".//xenc:EncryptedData", namespaces)
  if enc_data:
    encryption_method = enc_data.find(".//xenc:EncryptionMethod", namespaces)
    if encryption_method is not None:
      print(f"EncryptionMethod: {encryption_method.get('Algorithm')}")

  # EncryptedKey
  enc_keys = encrypted_assertion.findall(".//xenc:EncryptedKey", namespaces)
  print(f"Liczba EncryptedKey: {len(enc_keys)}")

  for i, ek in enumerate(enc_keys):
    print(f"\n--- EncryptedKey {i} ---")

    # EncryptionMethod w EncryptedKey
    ek_encryption = ek.find(".//xenc:EncryptionMethod", namespaces)
    if ek_encryption is not None:
      print(f"EncryptionMethod: {ek_encryption.get('Algorithm')}")

    # AgreementMethod
    agreement = ek.find(".//xenc11:AgreementMethod", namespaces)
    if agreement is not None:
      print(f"AgreementMethod: {agreement.get('Algorithm')}")

      # KeyDerivationMethod
      kdf = agreement.find(".//xenc11:KeyDerivationMethod", namespaces)
      if kdf is not None:
        print(f"KeyDerivationMethod: kdf.get('Algorithm')")
        # OriginatorKeyInfo
        originator =agreement.find(".//xenc:OriginatorKeyInfo", namespaces)
        if originator is not None:
          print("Znaleziono OriginatorKeyInfo")

        # CipherValue
        cipher_value = ek.find(".//xenc:CipherValue", namespaces)
        if cipher_value is not None and cipher_value.text:
          print(f"CipherValue (pierwsze 50 znaków): {cipher_value.text[:50]}...")

        # Użyj tej funkcji przed próbą deszyfrowania
        analyze_encryption_structure(root)


def decrypt_saml_assertion(xml_content, private_key_path):
  if isinstance(xml_content, str):
    xml_content = xml_content.encode('utf-8')
  try:
    root = etree.fromstring(xml_content, parser=etree.XMLParser(remove_blank_text=False))
  except etree.XMLSyntaxError as e:
    print(f"Error parsing XML: {e}")
    return None
  # analyze_encryption_structure(root)
  decrypted_xml=decrypt_saml_assertion_manual(root, settings.wk.enc_key)
  return decrypted_xml


def get_saml_attribute(tree, friendly_name, ns = {
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
}):
  # Ścieżka XPath: Szukamy atrybutu o danym FriendlyName i wchodzimy do jego wartości
  xpath_query = f"//saml2:AttributeStatement/saml2:Attribute[@FriendlyName='{friendly_name}']/saml2:AttributeValue/text()"
  result = tree.xpath(xpath_query, namespaces=ns)
  # Zwracamy pierwszy element listy lub None, jeśli nie znaleziono
  return result[0] if result else None

###########

async def run_in_threadpool(func: Callable, *args: Any) -> Any:
    """Uruchamia synchroniczną funkcję w puli wątków, aby nie blokować pętli asyncio."""
    loop = asyncio.get_running_loop()
    # loop.run_in_executor jest standardowym sposobem na osiągnięcie tego
    return await loop.run_in_executor(None, func, *args)

# --- Pomocnicze funkcje generujące ID, czas, RelayState ---
def get_authn_request_id() -> str:
  """Generuje unikalny ID dla AuthnRequest."""
  return f"ID-{uuid.uuid4()}"


def get_issue_instant() -> str:
  """Zwraca aktualny czas UTC w formacie SAML."""
  return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def generate_relay_state(size: int = 16) -> str:
  """Generuje losowy string RelayState."""
  allowed_chars = string.ascii_letters + string.digits
  return ''.join(random.choices(allowed_chars, k=size))


# --- Funkcje do generowania i podpisywania XML ---
async def get_signed_authn_request(xml_renderer: XMLRenderer, p12=False) -> str:
  """Generuje i podpisuje AuthnRequest XML."""
  xml_content = await xml_renderer.render_to_string(  # Użyj await
    'AuthnRequest.xml',
    {
      'authn_request_id': get_authn_request_id(), # ID
      'authn_request_issue_instant': get_issue_instant(), #IssueInstant
      'issuer': settings.wk.issuer, # Issuer
      'provider': settings.wk.provider, # Provider
      'acs_url': settings.wk.assertion_consumer_url, # AssertionConsumerServiceURL
    },
  )
  # add_sign musi być asynchroniczne lub opakowane w run_in_threadpool jeśli jest synchroniczne
  # Zakładam, że add_sign jest synchroniczne i nie blokuje pętli zdarzeń
  if p12:
    signed_xml = add_sign_p12( xml_content, settings.wk.sign_p12, settings.wk.password )
  else:
    signed_xml = add_sign(
      xml_content, settings.wk.sign_key, settings.wk.sign_cert )
  return signed_xml

# logout - generowanie i podpisywanie XML ---

async def get_signed_logout_request(xml_renderer: XMLRenderer, name_id, session_index, p12=False) -> str:
  # Generuje i podpisuje LogoutRequest XML. 
  xml_content = await xml_renderer.render_to_string(  # Użyj await
    'LogoutRequest.xml',
    {
      'request_id' : get_authn_request_id(), # ID ?
      'current_date' : get_issue_instant(),
      'issuer': settings.wk.issuer,  # Issuer
      'name_id':name_id,
      'session_index':session_index
    },
  )
  if p12:
    signed_xml = add_sign_p12( xml_content, settings.wk.sign_p12, settings.wk.password )
  else:
    signed_xml = add_sign(
      xml_content, settings.wk.sign_key, settings.wk.sign_cert )
  return signed_xml


# --- Funkcje do dekodowania odpowiedzi ---
def get_otherinfo(concat_kdf_params: etree._Element) -> str:
  """Concatenate ConcatKDFParams for KDF."""
  # Upewnij się, że atrybuty są pobierane prawidłowo (mogą wymagać sprawdzania None)
  algorithm_id = concat_kdf_params.attrib.get('AlgorithmID', '')
  party_u_info = concat_kdf_params.attrib.get('PartyUInfo', '')
  party_v_info = concat_kdf_params.attrib.get('PartyVInfo', '')
  otherinfo = ''.join([algorithm_id, party_u_info, party_v_info])
  return otherinfo

###############
# przez formularz!?

async def send_logout_async(signed_logout_request: str) -> httpx.Response:
  try:
    async with httpx.AsyncClient() as client:  # Użyj httpx.AsyncClient
      response = await client.post(  # Użyj await
        settings.wk.logout_url,
        data=signed_logout_request.encode('utf-8'),  # Dane do wysłania jako bytes
        timeout=settings.wk.timeout,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"}  # Typ treści dla SOAP
      )
      response.raise_for_status()  # Rzuć wyjątek dla statusów 4xx/5xx
      return response
  except httpx.RequestError as e:
    logger.exception(f'Logout  request failed: {e}')
    raise
  except httpx.HTTPStatusError as e:
    logger.exception(f'Logout returned error status {e.response.status_code}: {e.response.text}')
    raise

###############

async def resolve_artifact_async(saml_art: str, xml_renderer: XMLRenderer, p12=False) -> httpx.Response:
  """Rozdziela SAML Artifact do Identity Providera."""
  xml = await xml_renderer.render_to_string(  # Użyj await
    'ArtifactResolve.xml',
    {
      'artifact_resolve_issue_instant': get_issue_instant(),
      'artifact_resolve_artifact': saml_art,
      'issuer': settings.wk.issuer,
      'ID':get_authn_request_id()
    },
  )
  if p12:
    signed = add_sign_p12(  # Zakładam, że add_sign jest synchroniczne
      xml, settings.wk.enc_p12, settings.wk.password,
    )
  else:
    signed = add_sign(  # Zakładam, że add_sign jest synchroniczne
      xml, settings.wk.enc_key, settings.wk.enc_cert,
    )

  try:
    async with httpx.AsyncClient() as client:  # Użyj httpx.AsyncClient
      response = await client.post(  # Użyj await
        settings.wk.artifact_resolve_url,
        data=signed.encode('utf-8'),  # Dane do wysłania jako bytes
        timeout=settings.wk.timeout,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"}  # Typ treści dla SOAP
      )
      response.raise_for_status()  # Rzuć wyjątek dla statusów 4xx/5xx
      return response
  except httpx.RequestError as e:
    logger.exception(f'ArtifactResolve service request failed: {e}')
    raise
  except httpx.HTTPStatusError as e:
    logger.exception(f'ArtifactResolve service returned error status {e.response.status_code}: {e.response.text}')
    raise


def get_status_code(content: bytes) -> str:
  """Wyodrębnia StatusCode z odpowiedzi SAML."""
  try:
    # Lepsze użycie lxml dla bezpieczniejszego parsowania XML
    # from defusedxml.lxml import fromstring # Zalecane dla bezpieczeństwa
    tree = fromstring(content)

    # SAML 2.0 Status Code XPath (poprawione)
    status_code_elem = tree.find(
      './/{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')

    if status_code_elem is not None:
      nested_status_code_elem = status_code_elem.find('.//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
      if nested_status_code_elem is not None:
        return nested_status_code_elem.attrib.get('Value', '')
      else:
        return status_code_elem.attrib.get('Value', '')
    return ""  # Brak Status Code
  except Exception as e:
    logger.error(f"Failed to parse status code: {e}")
    return ""


def decode_cipher_value(content: bytes, server_private_key_path: str) -> bytes:
  """Dekoduje zaszyfrowaną asercję SAML."""
  # Użyj defusedxml.lxml.fromstring dla bezpieczeństwa
  try:
    tree = fromstring(content)

    # Sprawdzanie, czy elementy istnieją przed dostępem
    public_key_elem = tree.find('.//{http://www.w3.org/2009/xmldsig11#}PublicKey')
    cipher_value_elem = tree.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')
    user_attrs_elem = tree.find(
      './/{http://www.w3.org/2001/04/xmlenc#}EncryptedData/{http://www.w3.org/2001/04/xmlenc#}CipherData/{http://www.w3.org/2001/04/xmlenc#}CipherValue')
    concat_kdf_params_elem = tree.find('.//{http://www.w3.org/2009/xmlenc11#}ConcatKDFParams')

    if not all([public_key_elem, cipher_value_elem, user_attrs_elem, concat_kdf_params_elem]):
      raise ValueError("Brakujące elementy XML do dekodowania zaszyfrowanej asercji.")

    PUBLIC_KEY = public_key_elem.text
    CIPHER_VALUE = cipher_value_elem.text
    USER_ATTRS = user_attrs_elem.text
    concatKDFParams = concat_kdf_params_elem

    with open(server_private_key_path, 'rb') as f:
      server_private_key = load_pem_private_key(f.read(), None, default_backend())

    public_key_bytes = base64.b64decode(PUBLIC_KEY)
    curve = ec.SECP256R1()

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)

    # logger.debug('peer public key:\n%s', peer_public_key.public_bytes(
    #   encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    # ).decode())

    shared_key = server_private_key.exchange(ec.ECDH(), peer_public_key)
    # logger.debug('shared key: %s', shared_key)

    otherinfo = get_otherinfo(concatKDFParams)
    # logger.debug('otherinfo: %s', otherinfo)

    ckdf = ConcatKDFHash(
      algorithm=hashes.SHA256(),
      length=32,
      otherinfo=binascii.unhexlify(otherinfo.encode()),
      backend=default_backend()
    )

    cipher_bytes = base64.b64decode(CIPHER_VALUE)
    wrapping_key = ckdf.derive(shared_key)
    # logger.debug('wrapping key: %s', wrapping_key)

    session_key = aes_key_unwrap(wrapping_key, cipher_bytes, default_backend())
    user_attr_bytes = base64.b64decode(USER_ATTRS)
    nonce, tag = user_attr_bytes[:12], user_attr_bytes[-16:]  # GCM nonce length is 12 bytes

    # Użycie `cryptography.hazmat.primitives.ciphers.Cipher` dla GCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # decryptor.authenticate_tag(tag) # Tag jest przekazywany w konstruktorze modes.GCM
    decoded_saml = decryptor.update(user_attr_bytes[12:-16]) + decryptor.finalize()

    # logger.debug(decoded_saml)

    return decoded_saml
  except Exception as e:
    logger.exception(f"Error decoding cipher value: {e}")
    raise


def get_user(decoded_saml: bytes) -> WKUser:
  """Return WKUser instance based on decoded SAML assertion."""
  # Użyj defusedxml.lxml.fromstring dla bezpieczeństwa
  try:
    tree = fromstring(decoded_saml)

    # XPath-y dla danych użytkownika Login.gov.pl
    first_name = tree.find(
      './/{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentGivenNameType"]')
    last_name = tree.find(
      './/{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentFamilyNameType"]')
    date_of_birth = tree.find(
      './/{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:DateOfBirthType"]')
    pesel = tree.find(
      './/{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:PersonIdentifierType"]')

    # Upewnij się, że element istnieje i ma tekst
    return WKUser(
      first_name=first_name.text if first_name is not None else '',
      last_name=last_name.text if last_name is not None else '',
      date_of_birth=date_of_birth.text if date_of_birth is not None else '',
      pesel=pesel.text if pesel is not None else ''
    )
  except Exception as e:
    logger.error(f"Failed to parse user data from SAML: {e}")
    raise


def get_in_response_to(decoded_saml: bytes) -> str:
  """Return InResponseTo value from SAML assertion."""
  # Użyj defusedxml.lxml.fromstring dla bezpieczeństwa
  try:
    tree = fromstring(decoded_saml)
    elem = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData')
    if elem is not None:
      return elem.attrib.get("InResponseTo", "")
    return ""
  except Exception as e:
    logger.error(f"Failed to parse InResponseTo from SAML: {e}")
    raise

def load_pkcs12_certificate(pfx_file : str, password :str):
  with open(pfx_file, "rb") as cert_file:
    cert_content = cert_file.read()
    try:
        bpassword = password.encode('utf-8')
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            cert_content, bpassword,
            # backend=default_backend()
        )
    except ValueError as ex:
        raise ValueError("Failed to deserialize certificate in PEM or PKCS12 format") from ex
    if not private_key:
        raise ValueError("The certificate must include its private key")
    if not cert:
        raise ValueError("Failed to deserialize certificate in PEM or PKCS12 format")
    key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pem_sections = [key_bytes] + [c.public_bytes(Encoding.PEM) for c in [cert] + additional_certs]
    pem_bytes = b"".join(pem_sections)
    #fingerprint = cert.fingerprint(hashes.SHA1())  # nosec

    return (pem_bytes, key_bytes)
