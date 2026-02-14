import base64
import struct
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.backends import default_backend


def decrypt_saml_assertion_manual(root, private_key_path):
  """
  Ręczne odszyfrowanie asercji SAML.
  Naprawione błędy:
  1. XPath dla CipherData (pobieranie danych zamiast klucza).
  2. Definicja peer_public_bytes.
  3. Czyszczenie Base64 z białych znaków.
  """
  namespaces = {
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
    'xenc11': 'http://www.w3.org/2009/xmlenc11#',
    'dsig11': 'http://www.w3.org/2009/xmldsig11#',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'
  }

  # 1. Wczytaj klucz prywatny
  with open(private_key_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

  # 2. Znajdź elementy w XML
  try:
    # Główny element EncryptedData
    encrypted_data = root.xpath('//xenc:EncryptedData', namespaces=namespaces)[0]

    # Element EncryptedKey (wewnątrz KeyInfo)
    encrypted_key = encrypted_data.xpath('.//xenc:EncryptedKey', namespaces=namespaces)[0]

    # --- A. PARAMETRY KDF ---
    kdf_params = encrypted_key.xpath('.//xenc11:ConcatKDFParams', namespaces=namespaces)[0]
    algorithm_id = bytes.fromhex(kdf_params.get('AlgorithmID'))
    party_u_info = bytes.fromhex(kdf_params.get('PartyUInfo'))
    party_v_info = bytes.fromhex(kdf_params.get('PartyVInfo'))

    # --- B. KLUCZ PUBLICZNY NADAWCY (To brakowało!) ---
    # Szukamy w dsig11:PublicKey wewnątrz OriginatorKeyInfo
    pub_key_node = encrypted_key.xpath('.//dsig11:PublicKey', namespaces=namespaces)[0]
    peer_public_bytes = base64.b64decode("".join(pub_key_node.text.split()))

    # --- C. ZASZYFROWANY KLUCZ (Key CipherValue) ---
    key_cipher_node = encrypted_key.xpath('.//xenc:CipherValue', namespaces=namespaces)[0]
    key_cipher_bytes = base64.b64decode("".join(key_cipher_node.text.split()))

    # --- D. ZASZYFROWANE DANE (Data CipherValue) ---
    # Używamy poprawionego XPatha (bezpośrednie dziecko)
    data_cipher_node = encrypted_data.xpath('xenc:CipherData/xenc:CipherValue', namespaces=namespaces)[0]
    data_cipher_bytes = base64.b64decode("".join(data_cipher_node.text.split()))

    print(f"DEBUG: Rozmiar danych do odszyfrowania: {len(data_cipher_bytes)} bajtów")

  except IndexError as e:
    raise ValueError(f"Błąd struktury XML (brak elementu): {e}")

  # 3. ECDH - Wspólny sekret
  peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_bytes)
  shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

  # 4. ConcatKDF (Wariant "No SuppPubInfo")
  other_info = algorithm_id + party_u_info + party_v_info

  ckdf = ConcatKDFHash(
    algorithm=hashes.SHA256(),
    length=32,
    otherinfo=other_info,
    backend=default_backend()
  )
  kek = ckdf.derive(shared_secret)

  # 5. AES Key Unwrap
  try:
    cek = aes_key_unwrap(kek, key_cipher_bytes, default_backend())
    print("DEBUG: Klucz danych (CEK) poprawnie odpakowany.")
  except Exception as e:
    raise ValueError(f"Błąd Key Unwrap: {e}")

  # 6. AES-GCM Decrypt
  iv = data_cipher_bytes[:12]
  ciphertext = data_cipher_bytes[12:-16]
  tag = data_cipher_bytes[-16:]

  try:
    cipher = Cipher(algorithms.AES(cek), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(b"")  # Puste AAD

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    print("SUKCES: Asercja odszyfrowana.")

    return decrypted_data.decode('utf-8')

  except Exception as e:
    print(f"Błąd GCM details: IV={len(iv)}, Tag={len(tag)}, Ciphertext={len(ciphertext)}")
    raise ValueError(f"Błąd deszyfrowania (GCM): {e}")
