import base64

from fastapi import HTTPException, status

from jinja2 import Template
import xml.etree.ElementTree as ET
from lxml import etree


class LogoutRequestProcessor:
  def __init__(self):
    self.namespaces = {
      'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
      'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
      'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'ds': 'http://www.w3.org/2000/09/xmldsig#',
      'xenc': 'http://www.w3.org/2001/04/xmlenc#',
      'eidas': 'http://eidas.europa.eu/saml-extensions',
      'naturalperson': 'http://eidas.europa.eu/attributes/naturalperson'
    }

  def render_jinja_template(self, template_content, template_data):
    """
    Renderuje szablon Jinja2 z danymi
    """
    try:
      template = Template(template_content)
      rendered_xml = template.render(**template_data)
      return rendered_xml
    except Exception as e:
      raise ValueError(f"Błąd renderowania szablonu Jinja2: {e}")

  def prepare_for_signature(self, xml_content):
    """
    Przygotowuje XML do podpisu z canonicalizacją EXC-C14N
    """
    try:
      # Używamy lxml dla lepszej obsługi przestrzeni nazw i canonicalizacji
      parser = etree.XMLParser(remove_blank_text=True)
      root = etree.fromstring(xml_content.encode('utf-8'), parser)

      # Znajdź LogoutRequest - to będzie podpisywany element
      logout_request = root.find('.//saml2p:LogoutRequest', namespaces=self.namespaces)

      if logout_request is None:
        raise ValueError("Nie znaleziono elementu LogoutRequest")

      # Przygotowanie do canonicalizacji EXC-C14N
      # Ustaw atrybut ID dla referencji w podpisie
      if 'ID' in logout_request.attrib:
        logout_request.set('ID', logout_request.get('ID'))

      # Canonicalizacja elementu LogoutRequest (EXC-C14N)
      canonicalized = etree.tostring(
        logout_request,
        method='c14n',
        with_comments=False,
        exclusive=True,
        inclusive_ns_prefixes=['ds', 'saml2', 'saml2p', 'xenc'] #,'eidas','naturalperson']
      )

      return canonicalized.decode('utf-8')

    except Exception as e:
      raise ValueError(f"Błąd przygotowania do podpisu: {e}")

  def verify_template_structure(self, template_content):
    """
    Weryfikuje kompletność szablonu Jinja2
    """
    required_variables = [
      'destination',
      'request_id',
      'current_date',
      'issuer',
      'name_id',
      'session_index'
    ]

    missing_vars = []
    for var in required_variables:
      if f'{{{{ {var} }}}}' not in template_content:
        missing_vars.append(var)

    return missing_vars

  def validate_rendered_xml(self, xml_content):
    """
    Waliduje rendered XML po wstawieniu danych
    """
    issues = []

    try:
      root = ET.fromstring(xml_content)

      # Sprawdź wymagane elementy
      required_elements = {
        'LogoutRequest': './/{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest',
        'Issuer': './/{urn:oasis:names:tc:SAML:2.0:assertion}Issuer',
        'NameID': './/{urn:oasis:names:tc:SAML:2.0:assertion}NameID',
        'SessionIndex': './/{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex'
      }

      for name, xpath in required_elements.items():
        if root.find(xpath) is None:
          issues.append(f"Brak wymaganego elementu: {name}")

      # Walidacja atrybutów LogoutRequest
      logout_request = root.find('.//{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest')
      if logout_request is not None:
        required_attrs = ['Destination', 'ID', 'IssueInstant', 'Version']
        for attr in required_attrs:
          if attr not in logout_request.attrib:
            issues.append(f"Brak wymaganego atrybutu: {attr}")

        # Walidacja wartości atrybutów
        if 'IssueInstant' in logout_request.attrib:
          issue_instant = logout_request.get('IssueInstant')
          if not issue_instant.endswith('Z'):
            issues.append("IssueInstant powinien być w formacie UTC (kończyć się na 'Z')")

        if 'Version' in logout_request.attrib:
          if logout_request.get('Version') != '2.0':
            issues.append("Version powinna być '2.0'")

      # Walidacja NameID
      name_id = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
      if name_id is not None:
        nameid_format = name_id.get('Format')
        if nameid_format != 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified':
          issues.append("NameID Format powinien być 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'")

    except ET.ParseError as e:
      issues.append(f"Błąd parsowania XML: {e}")

    return issues

  def create_signed_logout_request_test(self, template_content, template_data):
    """
    Kompletny proces: renderowanie szablonu, walidacja i przygotowanie do podpisu
    """
    # 1. Renderowanie szablonu
    rendered_xml = self.render_jinja_template(template_content, template_data)
    print("Szablon poprawnie renderowany")

    # 2. Walidacja struktury
    issues = self.validate_rendered_xml(rendered_xml)
    if issues:
      raise ValueError(f"Błędy w rendered XML: {issues}")
    print("Struktura XML poprawna")

    # 3. Przygotowanie do podpisu
    canonicalized_xml = self.prepare_for_signature(rendered_xml)
    print("XML przygotowany do podpisu (canonicalizacja EXC-C14N)")

    return {
      'rendered_xml': rendered_xml,
      'canonicalized_xml': canonicalized_xml
    }

  def create_logout_request(self, template_content, template_data):
    """
    Kompletny proces: renderowanie szablonu, walidacja i przygotowanie do podpisu
    """
    rendered_xml = self.render_jinja_template(template_content, template_data)
    issues = self.validate_rendered_xml(rendered_xml)
    if issues:
      raise ValueError(f"Błędy w rendered XML: {issues}")
    canonicalized_xml = self.prepare_for_signature(rendered_xml)
    return canonicalized_xml

def create_soap_envelope(signed_xml):
  """
  Tworzy kopertę SOAP z podpisanym LogoutRequest
  """
  soap_envelope = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"/>
    <soap:Body>
        {signed_xml}
    </soap:Body>
</soap:Envelope>'''
  return soap_envelope

def signed_logout_request(template_path,template_data):
  processor = LogoutRequestProcessor()

  # Wczytaj szablon
  with open(template_path, 'r', encoding='utf-8') as f:
    template_content = f.read()

  # Weryfikacja szablonu
  missing_vars = processor.verify_template_structure(template_content)
  if missing_vars:
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Brakujące zmienne w szablonie: %s" % missing_vars)

  from core.config import settings
  from lib.xml_sign import add_sign
  canonicalized_xml=processor.create_logout_request(template_content, template_data)
  signed_xml = add_sign(canonicalized_xml, settings.wk.sign_key, settings.wk.sign_cert,
                      PrefixList="ds saml2 saml2p xenc",
                        #"ds saml2 saml2p xenc eidas naturalperson",
                        #"ds saml2 saml2p eidas naturalperson",
                      use_empty_reference=False)
  soap_message = create_soap_envelope(signed_xml)
  # debug!
  #debug_signature_process(canonicalized_xml, signed_xml, template_data)
  return soap_message


import hashlib

def debug_signature_process(original_unsigned_xml, final_signed_xml, template_data):
  """
  Porównaj proces podpisywania krok po kroku
  """
  print("=== DEBUG SIGNATURE ===")

  # Parsuj oba XML
  unsigned_root = etree.fromstring(original_unsigned_xml.encode())
  signed_root = etree.fromstring(final_signed_xml.encode())

  # 1. Znajdź LogoutRequest w obu dokumentach
  unsigned_lr = unsigned_root.find('.//saml2p:LogoutRequest')
  signed_lr = signed_root.find('.//saml2p:LogoutRequest')

  if unsigned_lr is None or signed_lr is None:
    print("❌ Nie znaleziono LogoutRequest")
    return

  # 2. Sprawdź ID
  unsigned_id = unsigned_lr.get('ID')
  signed_id = signed_lr.get('ID')
  print(f"ID w unsigned: {unsigned_id}")
  print(f"ID w signed: {signed_id}")

  # 3. Usuń podpis z signed dla porównania
  signature = signed_lr.find('{http://www.w3.org/2000/09/xmldsig#}Signature')
  if signature is not None:
    signed_lr.remove(signature)

  # 4. Canonicalizacja obu do porównania
  unsigned_canon = etree.tostring(unsigned_lr, method='c14n', exclusive=True)
  signed_canon = etree.tostring(signed_lr, method='c14n', exclusive=True)

  # 5. Porównaj digest
  unsigned_digest = hashlib.sha256(unsigned_canon).digest()
  signed_digest = hashlib.sha256(signed_canon).digest()

  print(f"Digest unsigned: {base64.b64encode(unsigned_digest).decode()}")
  print(f"Digest signed: {base64.b64encode(signed_digest).decode()}")

  # 6. Sprawdź czy są identyczne
  if unsigned_digest == signed_digest:
    print("✅ Digest się zgadza - struktura XML poprawna")
  else:
    print("❌ Digest się NIE zgadza - coś zmieniło się w XML")

  # 7. Sprawdź certyfikat
  x509_cert = signed_root.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
  if x509_cert is not None:
    cert_content = x509_cert.text.strip().replace('\n', '')
    print(f"Certyfikat: {cert_content[:50]}...")

#########################
def test():
  processor = LogoutRequestProcessor()

  # Wczytaj szablon
  with open('config/wk/LogoutRequest.xml', 'r', encoding='utf-8') as f:
    template_content = f.read()

  # Weryfikacja szablonu
  missing_vars = processor.verify_template_structure(template_content)
  if missing_vars:
    print("Brakujące zmienne w szablonie:", missing_vars)
    return
  else:
    print("Szablon zawiera wszystkie wymagane zmienne")

  try:
    # Kompletny proces
    result = processor.create_signed_logout_request_test(template_content, template_data)

    print("\nWyniki:")
    print(f"Rendered XML (pierwsze 200 znaków): {result['rendered_xml'][:200]}...")
    print(f"Canonicalized XML (pierwsze 200 znaków): {result['canonicalized_xml'][:200]}...")
    from core.config import settings
    from lib.xml_sign import add_sign
    canonicalized_xml=processor.create_logout_request(template_content, template_data)
    signed_xml = add_sign(canonicalized_xml, settings.wk.sign_key, settings.wk.sign_cert,
                        PrefixList="ds saml2 saml2p xenc", #"ds saml2 saml2p eidas naturalperson",
                        use_empty_reference=True)
    print(f"Podpisany XML (pierwsze 200 znaków): {signed_xml[:200]}...")
    soap_message = create_soap_envelope(signed_xml)
    print(f"Koperta SOAP (pierwsze 200 znaków): {soap_message[:200]}...")
  except Exception as e:
    print(f"❌ Błąd: {e}")


if __name__ == "__main__":
  test()