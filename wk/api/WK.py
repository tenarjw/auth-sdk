# api.WK.py
import uuid
from datetime import timezone, datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Form, Request, Depends, HTTPException, status
#from fastapi.logger import logger
import base64
import os

from sqlalchemy.orm import Session

from fastapi.responses import HTMLResponse
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse

from core.config import settings
from crud.crud_user import get_user_by_wk_ident, crud_user
from lib import saml_utils
from lib.saml_logout import signed_logout_request
from lib.saml_utils import (
  get_signed_authn_request, generate_relay_state,
  resolve_artifact_async, get_status_code, get_signed_logout_request, verify_saml_signatures, decrypt_saml_assertion
)
from lib.token import create_token
from lib.xml_render import XMLRenderer
from xml.etree.ElementTree import fromstring, tostring
from lib.xml_sign import add_sign
from schemas import wk_schemas, token_schemas
from api.dependencies import get_db

from lxml import etree
import xmlsec

import logging

from services import wk_service
from services.wk_service import token_for_wk_user, token2session

logger = logging.getLogger(__name__)

router = APIRouter(
  prefix="",  # Upewnij się, że ten prefix pasuje do głównego routera
  tags=["Węzeł Krajowy (Login.gov.pl)"]
)

# Inicjalizuj XMLRenderer raz na całą aplikację
#xml_renderer = XMLRenderer(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))
xml_renderer = XMLRenderer(directory=os.path.join(os.path.dirname(__file__), "..",settings.wk.templates))

@router.get("/login")
async def login_wk_init(
    code : str,
    db: Session = Depends(get_db)
):
  """
  Generuje żądanie SAML AuthnRequest i przekierowuje użytkownika do IdP.
  """
  if code!='pseudoklucz':
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nieprawidłowy klucz.")
  logger.debug("Generating AuthnRequest for Login.gov.pl")
  signed_request_xml = await get_signed_authn_request(xml_renderer)
  #saml_request=signed_request_xml.encode('utf-8')
  logger.debug(signed_request_xml)
  saml_request_b64 = base64.b64encode(signed_request_xml.encode('utf-8')).decode('utf-8')
  relay_state = generate_relay_state()

  tree = fromstring(signed_request_xml)
  authn_request_id = tree.attrib.get('ID')

  if authn_request_id:
    dbresult=wk_service.create_wk(db, wk_schemas.WKSession(
      relay_state=relay_state,
      authn_request_id=authn_request_id
    ))
    logger.debug(f"Stored RelayState: {relay_state} for AuthnRequest ID: {authn_request_id},db={dbresult}")
  else:
    logger.warning("AuthnRequest ID not found in generated XML.")
    raise HTTPException(status_code=500, detail="Nie udało się wygenerować ID żądania SAML.")

  # Zbuduj parametry zapytania
  params = {
    'SAMLRequest': saml_request_b64,
    'RelayState': relay_state
  }

  # Zbuduj pełny URL i zwróć przekierowanie
  # WK wymaga przesłania formularza POST - więc nie wysyłamy SAMLRequest od razu na sso
  #redirect_url = f"{settings.wk.sso_url}?{urlencode(params)}"
  #return RedirectResponse(url=redirect_url)
  redirect_url = f"{settings.wk.saml_post_url}?{urlencode(params)}"
  #return RedirectResponse(url=settings.wk.saml_post_url)#redirect_url)
  #return RedirectResponse(url=redirect_url, status_code=303)

  saml_post_url = "https://int-podmiotyzewnetrzne.login.gov.pl/login/SingleSignOnService" # "https://int.login.gov.pl/login/SingleSignOnService" #"https://e-talar.com/saml"
  html_content = f"""
<!DOCTYPE html><HTML><BODY Onload="document.forms[0].submit()">
<FORM METHOD="POST" ACTION="https://int-podmiotyzewnetrzne.login.gov.pl/login/SingleSignOnService"><INPUT TYPE="HIDDEN" NAME="SAMLRequest" VALUE='{saml_request_b64}'/>
<INPUT TYPE="HIDDEN" NAME="RelayState" VALUE='{relay_state}'/>
<NOSCRIPT><P>JavaScript jest wyłączony. Rekomendujemy włączenie. Aby kontynuować, proszę nacisnąć przycisk poniżej.</P><INPUT TYPE="SUBMIT" VALUE="Kontynuuj" /></NOSCRIPT>
</FORM></BODY></HTML>  
      """
  #
  return HTMLResponse(content=html_content)


def extract_saml_response(artifact_response_xml: str,
                          sp_private_key_path: str):
    """
    Przetwarza odpowiedź ArtifactResponse z Węzła Krajowego:
    - weryfikuje podpisy,
    - odszyfrowuje asercję,
    - zwraca dane użytkownika (NameID + atrybuty).
    """
    # NIGDY nie używaj remove_blank_text=True przy weryfikacji podpisu!
    # To zmienia strukturę XML i psuje hash podpisu (C14N).
    parser = etree.XMLParser(remove_blank_text=False)
    # Jeśli artifact_response_xml to string, zakoduj go. Jeśli bytes, zostaw.
    if isinstance(artifact_response_xml, str):
      artifact_response_xml = artifact_response_xml.encode('utf-8')

    logger.info(f'artifact_response: {artifact_response_xml}')
    root = etree.fromstring(artifact_response_xml, parser) # .encode('utf-8')

    # weryfikuje podpisy
    dsok = verify_saml_signatures(root)
    logger.info(f"\nPodpisy: %s" % dsok)

    # odszyfruj asercję
    try:
      decrypted_assertion = decrypt_saml_assertion(artifact_response_xml, sp_private_key_path)
      assertion_root = etree.fromstring(decrypted_assertion)
    except Exception as e:
      logger.error(f"Błąd: {e}")
    logger.info(f'decrypted_assertion: {decrypted_assertion}')
    # Parsuj dane z asercji
    ns = {'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}

    # NameID oraz SessionIndex (będzie potrzebne dla Logout)
    name_id_node = assertion_root.find('.//saml2:Subject/saml2:NameID', namespaces=ns)
    name_id = name_id_node.text if name_id_node is not None else None
    name_id_format = name_id_node.get('Format') if name_id_node is not None else None
    authn_statement = assertion_root.find('.//saml2:AuthnStatement', namespaces=ns)
    session_index = authn_statement.get('SessionIndex') if authn_statement is not None else None
    # authn_request_id - powiązanie z zapytaniem
    subject_confirmation_node = assertion_root.find('.//saml2:Subject/saml2:SubjectConfirmation/saml2:SubjectConfirmationData',
                                          namespaces=ns)
    authn_request_id=subject_confirmation_node.get('InResponseTo')
    # Otrzymane wartości atrybutów

    attrs = {}
    for attr in assertion_root.findall('.//saml2:Attribute', namespaces=ns):
        name = attr.get('Name')
        value_el = attr.find('.//saml2:AttributeValue', namespaces=ns)
        attrs[name] = value_el.text if value_el is not None else None

    result = {
      'authn_request_id':authn_request_id,
      'name_id': name_id,
      'name_id_format': name_id_format,
      'session_index': session_index,
      'attributes': attrs
    }
    return result

##############################################################################################################

@router.post("/acs")
@router.get("/acs")  # obsługuje też GET z Węzła
async def acs_endpoint(request: Request,
                       SAMLart: Optional[str] = Form(None),
                       RelayState: Optional[str] = Form(None),
                       SAMLResponse: Optional[str] = Form(None),
                       db: Session = Depends(get_db)):
    logger.info("Otrzymano żądanie na /acs (Artifact Binding)")
    logger.info(f"SAMLart={SAMLart}, RelayState={RelayState}")

    if request.method == "GET":
        params = dict(request.query_params)
        SAMLart = params.get("SAMLart")
        RelayState = params.get("RelayState")

    if not SAMLart:
        return HTMLResponse("<h3>Brak parametru SAMLart</h3>", status_code=400)

    redirect_url = f"{settings.app.frontend_url}/login/callback"

    # Budujemy ArtifactResolve i wysyłamy do WK
    test=False # gry test - pobieramy odpowiedź z pliku i nie wysyłamy
    if test:
      f=open('../response.xml')
      artifact_response_xml=f.read()
      f.close()
    else:
      #artifact_resolve_xml = build_artifact_resolve(SAMLart)
      try:
        response = await resolve_artifact_async(SAMLart, xml_renderer)
        artifact_response_xml = response.text
      except  Exception as e:
          logger.exception(f"Błąd przetwarzania odpowiedzi SAML: {e}")
          return RedirectResponse(url=redirect_url, status_code=302)
  #        return HTMLResponse(f"<h3>Błąd SAML: {e}</h3>", status_code=500)
    # Odszyfruj i zweryfikuj asercję
    try:
        saml_data = extract_saml_response(
            artifact_response_xml, #?.encode('utf-8'),
            sp_private_key_path=settings.wk.enc_key,
        )
        logger.info(f"SAML dane użytkownika: {saml_data}")
    except Exception as e:
        logger.exception(f"Błąd przetwarzania odpowiedzi SAML: {e}")
        return RedirectResponse(url=redirect_url, status_code=302)
#        return HTMLResponse(f"<h3>Błąd SAML: {e}</h3>", status_code=500)
    # Zaloguj użytkownika w  aplikacji
    first_name = saml_data['attributes'].get('http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName')
    last_name=saml_data['attributes'].get('http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName')
    if first_name:
      name=first_name+' '+last_name
    else:
      name = last_name
    authn_request_id=saml_data['authn_request_id']
    wk_ident=saml_data['attributes'].get('http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier')
    (user_token, user_email) = token_for_wk_user(db, wk_ident, name, saml_data.get('name_id'),
                                   saml_data.get('session_index'), authn_request_id)
    # Przekieruj do frontendu z tokenem lub stanem RelayState
    if RelayState:
      redirect_url += f"?email={user_email}&state={RelayState}"
    else:
      redirect_url += f"?email={user_email}&token={user_token}"

    return RedirectResponse(url=redirect_url, status_code=302)

######### wylogowanie

# Endpoint inicjujący wylogowanie (SP-initiated SLO)
@router.get("/logout", response_model=token_schemas.ReturnBasic)
async def logout_wk(
    token: str,
    db: Session = Depends(get_db)
):
  logger.info(f'Logout')
  # Pobierz dane sesji z bazy na podstawie tokenu
  (name_id, session_index) = token2session(db, token)
  if not (name_id and session_index):
    return  token_schemas.ReturnBasic(code=-1, result="Token nie należy do żadnej aktywnej sesji")
  logout_request_id = f"ID-{uuid.uuid4()}"  # NOWY ID
  # Renderowanie z przekazaniem Destination (ważne dla podpisu!)
  #slo_url = "https://int-podmiotyzewnetrzne.login.gov.pl/logout/SingleLogoutService"
  template_data={
      'request_id': logout_request_id,
      'current_date': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
      'issuer': settings.wk.issuer,
      'name_id': name_id,
      'session_index': session_index,
      'destination': settings.wk.logout_url  # slo_url do szablonu w atrybucie Destination
    }
  signed_xml = signed_logout_request('config/wk/LogoutRequest.xml', template_data)
  logger.info("Wysyłany SAOP: "+signed_xml)
  async with httpx.AsyncClient() as client:
    response = await client.post(
      settings.wk.logout_url,
      content=signed_xml.encode('utf-8'),
      timeout=settings.wk.timeout,
      headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '""' #"http://www.oasis-open.org/committees/security"
      }
    )
    logger.info(f"Status: {response.status_code}")
    logger.info(f"Response headers: {dict(response.headers)}")
    logger.info(f"Response body: {response.text}")
    response.raise_for_status()  # Rzuć wyjątek dla statusów 4xx/5xx
    logger.exception(f'Logout wysłany: {name_id}')
    return  token_schemas.ReturnBasic(code=0, result="Zostałeś wylogowany z login.gov.pl")

