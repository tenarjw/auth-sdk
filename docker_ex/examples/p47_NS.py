from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_nonce():
  """Generuje losowy nonce (np. 16 bajtów)."""
  return os.urandom(16)

def encrypt(key, plaintext, iv=None):
  """Szyfruje plaintext kluczem symetrycznym (AES-CBC)."""
  if not isinstance(plaintext, bytes):
    plaintext = plaintext.encode('utf-8')
  if iv is None:
    iv = os.urandom(16)  # Wektor inicjalizacyjny

  # Algorytm AES ma rozmiar bloku 128 bitów
  padder = padding.PKCS7(algorithms.AES.block_size).padder()
  padded_data = padder.update(plaintext) + padder.finalize()
  # Without padding:
  # The length of the provided data is not a multiple of the block length.

  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(padded_data) + encryptor.finalize()
  return iv + ciphertext

def decrypt(key, ciphertext_with_iv):
  """Odszyfrowuje dane i usuwa padding."""
  # Wyodrębnij IV (pierwsze 16 bajtów)
  iv = ciphertext_with_iv[:16]
  ciphertext = ciphertext_with_iv[16:]
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
  decryptor = cipher.decryptor()
  # Odszyfruj dane - +  padding
  padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
  # Usuń padding:
  unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
  plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
  return plaintext


# Przykład symulacji
if __name__ == "__main__":
  key_A = os.urandom(16)  # Klucz długoterminowy A
  key_B = os.urandom(16)  # Klucz długoterminowy B
  session_key = os.urandom(16)  # Klucz sesyjny K
  ra = generate_nonce()
  ticket = encrypt(key_B, b"session_key:" + session_key + b":Alice")
  response = encrypt(key_A, ra + b":Bob:" + session_key + b"ticket:" + ticket)
  print("Odpowiedź (A):", response.hex())
  responsedecrypt=decrypt(key_A,response)
  print('Sprawdzenie:')
  (nonce,rest)=responsedecrypt.split(b":Bob:")
  (key,dticket)=rest.split(b"ticket:")
  print('Ticket:',ticket.hex())
  print('Odszyfrowany ticket: ',dticket.hex())
  if ticket==dticket and ra==nonce:
    print('Algorytm działa poprawnie!')
  else:
    print('Coś nie działa!!!')
