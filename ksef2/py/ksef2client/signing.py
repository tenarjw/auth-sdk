import tempfile
import subprocess
from lxml import etree
from typing import Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import base64
from datetime import datetime, timezone
import os

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"
SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"


def _build_qualifying_properties_xml(cert, signature_id="Signature", signed_props_id="SignedProperties"):
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_digest = hashes.Hash(hashes.SHA256())
    cert_digest.update(cert_der)
    digest_b64 = base64.b64encode(cert_digest.finalize()).decode("ascii")

    issuer_name = cert.issuer.rfc4514_string()
    serial_number = str(cert.serial_number)
    signing_time = datetime.now(timezone.utc).isoformat()

    qprops_xml = f'''<xades:QualifyingProperties Target="#{signature_id}" xmlns:xades="{XADES_NS}" xmlns:ds="{DS_NS}">
  <xades:SignedProperties Id="{signed_props_id}">
    <xades:SignedSignatureProperties>
      <xades:SigningTime>{signing_time}</xades:SigningTime>
      <xades:SigningCertificate>
        <xades:Cert>
          <xades:CertDigest>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>{digest_b64}</ds:DigestValue>
          </xades:CertDigest>
          <xades:IssuerSerial>
            <ds:X509IssuerName>{issuer_name}</ds:X509IssuerName>
            <ds:X509SerialNumber>{serial_number}</ds:X509SerialNumber>
          </xades:IssuerSerial>
        </xades:Cert>
      </xades:SigningCertificate>
    </xades:SignedSignatureProperties>
  </xades:SignedProperties>
</xades:QualifyingProperties>'''

    return etree.fromstring(qprops_xml)


def sign_auth_request_with_xmlsec(xml_input: Union[bytes, str], pfx_path: str, pfx_password: str) -> bytes:
    """Podpisuje AuthTokenRequest zgodnie z KSeF (bez Id na root, Reference URI="")."""
    if isinstance(xml_input, str):
        xml_bytes = xml_input.encode("utf-8")
    else:
        xml_bytes = xml_input

    parser = etree.XMLParser(remove_blank_text=False)
    root = etree.fromstring(xml_bytes, parser=parser)

    # Wczytaj certyfikat i klucz prywatny
    pfx_data = open(pfx_path, "rb").read()
    private_key, cert, additional = pkcs12.load_key_and_certificates(pfx_data, pfx_password.encode())
    if cert is None:
        raise ValueError("Nie udało się odczytać certyfikatu z PFX")

    # Zbuduj XAdES QualifyingProperties
    qprops = _build_qualifying_properties_xml(cert, signature_id="Signature", signed_props_id="SignedProperties")

    # Szablon podpisu – Reference URI="" dla całego dokumentu (zgodnie z C#)
    sig_template = f'''
<ds:Signature Id="Signature" xmlns:ds="{DS_NS}">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue></ds:DigestValue>
    </ds:Reference>
    <ds:Reference Type="{SIGNED_PROPERTIES_TYPE}" URI="#SignedProperties">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue></ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue></ds:SignatureValue>
  <ds:KeyInfo>
    <ds:X509Data>
      <ds:X509Certificate></ds:X509Certificate>
    </ds:X509Data>
  </ds:KeyInfo>
</ds:Signature>
'''.strip()

    sig_elem = etree.fromstring(sig_template)

    # Dodaj ds:Object z QualifyingProperties
    obj = etree.Element("{%s}Object" % DS_NS)
    obj.append(qprops)
    sig_elem.append(obj)

    # Dołącz Signature do dokumentu
    root.append(sig_elem)

    # Zapisz i podpisz xmlsec1
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_input = os.path.join(tmpdir, "input.xml")
        tmp_output = os.path.join(tmpdir, "signed.xml")

        with open(tmp_input, "wb") as f:
            f.write(etree.tostring(root, xml_declaration=True, encoding="utf-8", pretty_print=False))

        cmd = [
            "xmlsec1",
            "--sign",
            "--output", tmp_output,
            "--pkcs12", pfx_path,
            "--pwd", pfx_password,
            tmp_input
        ]

        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(f"xmlsec1 failed:\nstdout:\n{proc.stdout.decode()}\nstderr:\n{proc.stderr.decode()}")

        return open(tmp_output, "rb").read()
