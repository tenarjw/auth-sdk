import hashlib
import base64
from typing import Optional
from .models import SendInvoiceRequest, EncryptionInfo
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256  # <-- DODANY IMPORT


def create_send_invoice_request(
    xml_content: bytes,
    encrypted_xml_content: bytes,
    encryption_info: EncryptionInfo,
    offline_mode: bool = False,
    hash_of_corrected_invoice: Optional[str] = None
) -> SendInvoiceRequest:
  # Tworzy obiekt SendInvoiceRequest z XML faktury zgodnie z KSeF 2.0

  original_hash = hashlib.sha256(xml_content)
  original_hash_value = base64.b64encode(original_hash.digest()).decode('ascii')

  encrypted_hash = hashlib.sha256(encrypted_xml_content)
  encrypted_hash_value = base64.b64encode(encrypted_hash.digest()).decode('ascii')

  return SendInvoiceRequest(
    invoiceHash=original_hash_value,
    invoiceSize=len(xml_content),
    encryptedInvoiceHash=encrypted_hash_value,
    encryptedInvoiceSize=len(encrypted_xml_content),
    encryptedInvoiceContent=base64.b64encode(encrypted_xml_content).decode('ascii'),
    offlineMode=offline_mode,
    hashOfCorrectedInvoice=hash_of_corrected_invoice
  )


def calculate_invoice_hash(xml_content: bytes) -> str:
  # Oblicza hash SHA256 faktury w formacie Base64
  hash_obj = hashlib.sha256(xml_content)
  return base64.b64encode(hash_obj.digest()).decode('ascii')


def prepare_invoice_for_sending(
    xml_content: bytes,
    symmetric_key: bytes,
    initialization_vector: bytes
) -> tuple[bytes, str, str]:
  # Przygotowuje fakturę do wysłania - szyfrowanie AES-256-CBC 
  original_hash = calculate_invoice_hash(xml_content)

  cipher = AES.new(symmetric_key, AES.MODE_CBC, initialization_vector)
  padded_data = pad(xml_content, AES.block_size)
  encrypted_content = cipher.encrypt(padded_data)

  encrypted_hash = calculate_invoice_hash(encrypted_content)

  return encrypted_content, original_hash, encrypted_hash


def create_encryption_info(symmetric_key: bytes, public_key_pem: str, iv: bytes) -> EncryptionInfo:
  # Tworzy EncryptionInfo z kluczem symetrycznym zaszyfrowanym RSA-OAEP
  public_key = RSA.import_key(public_key_pem)

  # Uwaga! obiektu SHA256 z Crypto.Hash, bo funkcja z hashlib stwarza problemy z kompatybilnością
  cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

  encrypted_key = cipher_rsa.encrypt(symmetric_key)

  return EncryptionInfo(
    encryptedSymmetricKey=base64.b64encode(encrypted_key).decode('ascii'),
    initializationVector=base64.b64encode(iv).decode('ascii')
  )