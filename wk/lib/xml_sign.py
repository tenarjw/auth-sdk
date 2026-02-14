import logging
from defusedxml.lxml import fromstring, tostring
import xmlsec
from lxml import etree
#from fastapi.logger import logger

# zmiana 3 listopada 2025 use_empty_reference: bool = True -> False
def add_sign(xml: str, key_path: str, cert_path: str, use_empty_reference: bool = False,
             debug: bool = True, PrefixList="ds saml2 saml2p xenc") -> str:
    """
    Podpisuje SAML AuthnRequest:
    - jeśli use_empty_reference=True -> Reference URI="" (podpis dokumentu wg dokumentacji WK)
    - jeśli False -> Reference URI="#ID-..." (podpis względem elementu z ID)
    - tworzy InclusiveNamespaces bez prefixu (xmlns="...")
    Args:
        xml (str): SAML assertion
        key_path (Path): path enc key
        cert_path (Path): path to cert/pem
        debug (boolean): xmlsec enable debug trace

    Returns:
        str: signed SAML assertion

    Raises:
        Exception: if xml is empty
    """
    if not xml:
        raise ValueError("Empty xml")

    # parse
    root = fromstring(xml.encode("utf-8"), forbid_dtd=True)

    # utwórz węzeł Signature (ds namespace prefix 'ds')
    signature = xmlsec.template.create(
        root,
        xmlsec.Transform.EXCL_C14N,                 # CanonicalizationMethod
        xmlsec.Transform.ECDSA_SHA256,              # SignatureMethod (algorytm)
        ns='ds'
    )

    # znajdź Issuer i wstaw Signature zaraz za nim
    issuer = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    if issuer is None:
        # fallback: wstaw na początek root'a
        root.insert(0, signature)
    else:
        issuer.addnext(signature)

    # element który chcemy podpisać (np. AuthnRequest)
    elem_to_sign = issuer.getparent() if issuer is not None else root

    # jeżeli mamy ID i chcemy referencję po ID — dodaj ID do xmlsec tree
    elem_id = elem_to_sign.get('ID')
    if elem_id:
        xmlsec.tree.add_ids(elem_to_sign, ['ID'])

    # wybór URI reference: pusty string "" lub "#ID-..."
    if use_empty_reference:
        uri_val = ""   # dokumentacja WK pokazuje Reference URI=""
    else:
        uri_val = f"#{elem_id}" if elem_id else ""

    # add reference (SHA256)
    ref = xmlsec.template.add_reference(signature, xmlsec.Transform.SHA256, uri=uri_val)

    # add transforms: enveloped, then exclusive-c14n
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    transform = xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)

    # === ważne: dodaj InclusiveNamespaces jako element w domyślnej przestrzeni nazw (bez prefixu) ===
    # tworzymy element z QName wskazującym namespace exc-c14n i ustawiamy nsmap={None: URI}
    inc_qname = "{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces"
    inclusive = etree.SubElement(transform, inc_qname, nsmap={None: "http://www.w3.org/2001/10/xml-exc-c14n#"})
    inclusive.set("PrefixList", PrefixList) #"ds saml2 saml2p xenc")

    # KeyInfo / cert
    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_x509_data(key_info)

    # podpisujemy
    xmlsec.enable_debug_trace(debug)
    dsig_ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(key_path, xmlsec.KeyFormat.PEM, None)
    # załaduj certyfikat do klucza (umieści X509 w KeyInfo)
    key.load_cert_from_file(cert_path, xmlsec.KeyFormat.PEM)
    dsig_ctx.key = key

    ################# problem: biblioteka xmlsec zapisuje podpis w dwóch wierszach!!!
    # sign
    niepodpisany=tostring(root,pretty_print=True).decode('utf-8')
    print("Log: Rozpoczynam podpisywanie...")
    dsig_ctx.sign(signature)
    print("Log: Podpisywanie zakończone.")

    # === POCZĄTEK POPRAWKI ===
    # Obejście problemu łamania wierszy przez bibliotekę xmlsec.
    # Musimy ręcznie "wyczyścić" tekst w węźle SignatureValue.

    # 1. Zdefiniuj przestrzeń nazw 'ds' (tak jak w XML)
    NS_MAP = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}

    # 2. Znajdź węzeł <ds:SignatureValue> wewnątrz <ds:Signature>
    sig_value_node = signature.find('ds:SignatureValue', namespaces=NS_MAP)

    if sig_value_node is not None:
        # 3. Pobierz jego tekst (który zawiera znaki nowej linii)
        original_base64 = sig_value_node.text

        # 4. Wyczyść tekst ze wszystkich białych znaków (spacji, tabów, \n)
        cleaned_base64 = ''.join(original_base64.split())

        # 5. Ustaw oczyszczony tekst z powrotem jako zawartość węzła
        sig_value_node.text = cleaned_base64
        print("Log: Poprawiono formatowanie SignatureValue.")
    else:
        # To nie powinno się zdarzyć, jeśli szablon był poprawny
        raise Exception("Krytyczny błąd: Nie znaleziono węzła ds:SignatureValue po podpisaniu!")

    # === KONIEC POPRAWKI ===

    # zwróć serializowany xml (bez pretty_print by uniknąć zmian w białych znakach)
    return tostring(root).decode('utf-8')

"""
# 2. Utwórz obiekt klucza i załaduj certyfikaty z pamięci
dsig_ctx = xmlsec.SignatureContext()

# Zamiast from_file, użyj from_memory, przekazując bajty klucza prywatnego
sign_key = xmlsec.Key.from_memory(key_pem_data, xmlsec.KeyFormat.PEM, None)

# Zamiast load_cert_from_file, użyj load_cert_from_memory.
# Można tu przekazać `pem_all_data`, ponieważ funkcja inteligentnie
# odnajdzie i wczyta tylko bloki certyfikatów (-----BEGIN CERTIFICATE-----).
sign_key.load_cert_from_memory(pem_all_data, xmlsec.KeyFormat.PEM)
"""

def add_sign_p12(xml, pfx_path, pfx_password, use_empty_reference: bool = True, debug=False):
    # do poprawienia
    return ""
    from lib.saml_utils import load_pkcs12_certificate
    if xml is None or xml == '':
        raise Exception('Empty string supplied as input')

    elem = fromstring(xml.encode('utf-8'), forbid_dtd=True)

    sign_algorithm_transform = xmlsec.Transform.ECDSA_SHA256

    signature = xmlsec.template.create(
        elem, xmlsec.Transform.EXCL_C14N, sign_algorithm_transform, ns='ds',
    )

    issuer = elem.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    if issuer:
        issuer = issuer[0]
        issuer.addnext(signature)
        elem_to_sign = issuer.getparent()

    elem_id = elem_to_sign.get('ID', None)
    if elem_id is not None:
        if elem_id:
            elem_id = f'#{elem_id}'

    xmlsec.enable_debug_trace(debug)
    xmlsec.tree.add_ids(elem_to_sign, ['ID'])

    digest_algorithm_transform = xmlsec.Transform.SHA256

    ref = xmlsec.template.add_reference(
        signature, digest_algorithm_transform, uri=elem_id,
    )
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)

    transform = xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
    # Dodanie wymaganych prefiksów wg dokumentacji Węzła Krajowego:
    from lxml import etree
    inclusive = etree.SubElement(
        transform,
        "{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces",
    )
    inclusive.set("PrefixList", "ds saml2 saml2p xenc")

    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_x509_data(key_info)


    pem_all_data, key_pem_data = load_pkcs12_certificate(pfx_path, pfx_password)

    # Utwórz obiekt klucza i załaduj certyfikaty z pamięci
    dsig_ctx = xmlsec.SignatureContext()

    # Zamiast from_file, użyj from_memory, przekazując bajty klucza prywatnego
    sign_key = xmlsec.Key.from_memory(key_pem_data, xmlsec.KeyFormat.PEM, None)

    # Zamiast load_cert_from_file, użyj load_cert_from_memory.
    # Można tu przekazać `pem_all_data`, ponieważ funkcja inteligentnie
    # odnajdzie i wczyta tylko bloki certyfikatów (-----BEGIN CERTIFICATE-----).
    sign_key.load_cert_from_memory(pem_all_data, xmlsec.KeyFormat.PEM)

    dsig_ctx.key = sign_key
    dsig_ctx.sign(signature)

    return tostring(elem).decode()


def test_xsign(xml, key,manager):
    from lxml import etree
    xml = etree.parse(xml)
    manager = xmlsec.KeysManager()
    #key = xmlsec.Key.from_file("cert.pem", xmlsec.KeyFormat.PEM)
    manager.add_key(key)
    ctx = xmlsec.SignatureContext(manager)
    sign_node = xml.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    ctx.verify(sign_node)
    print("Podpis poprawny")
