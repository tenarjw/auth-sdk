import sys
import os
import random
import string
import struct
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fcrypt import encrypt_data, decrypt_data


def generate_random_data(length=100):
  """Generuje losowy ciąg znaków o zadanej długości."""
  return ''.join(random.choices(string.ascii_letters + string.digits + ' \n', k=length))

def priv_key(filename):
  """Sprawdza istnienie pliku, wczytuje lub generuje dane."""
  if os.path.exists(filename):
    with open(filename, 'rb') as file:
      private_pem = file.read()
      private_key_loaded = serialization.load_pem_private_key(
        private_pem,
        password=None,  # Podaj hasło, jeśli klucz jest zaszyfrowany
        backend=default_backend()
      )
    return private_key_loaded
  else:
    # Generowanie pary kluczy RSA
    private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
    )
    rsa_public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
      # Bez hasła; użyj serialization.BestAvailableEncryption(b"hasło") dla szyfrowania
    )
    with open(filename, 'wb') as file:
      file.write(private_pem)
    public_pem = rsa_public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pfilename=filename[:-4]+'.pub'
    with open(pfilename, 'wb') as file:
      file.write(public_pem)
    return private_key

def pub_key(filename):
  with open(filename, 'rb') as file:
    public_pem = file.read()
    public_key_loaded = serialization.load_pem_public_key(
      public_pem,
      backend=default_backend()
    )
  return public_key_loaded

def unpack_data(output):
  # Odczytaj pierwsze 2 bajty jako długość encrypted_key
  key_length = struct.unpack("!H", output[:2])[0]
  # Oblicz pozycję początku encrypted_data
  data_length_start = 2 + key_length
  # Odczytaj encrypted_key
  encrypted_key = output[2:2 + key_length]
  # Odczytaj kolejne 2 bajty jako długość encrypted_data
  data_length = struct.unpack("!H", output[data_length_start:data_length_start + 2])[0]
  # Odczytaj encrypted_data
  encrypted_data = output[data_length_start + 2:data_length_start + 2 + data_length]
  return encrypted_key, encrypted_data

if __name__ == "__main__":
  action = sys.argv[1]
  if action=='rsa':
    priv_key('test.key')
    exit(0)
  in_filename = sys.argv[2]
  out_filename = sys.argv[3]
  if action=='crypt':
    # Szyfrowanie pliku
    rsa_public_key=pub_key('test.pub')
    with open(in_filename, 'rb') as file:
      input_data = file.read()
    (encrypted_key, encrypted_data) = encrypt_data(rsa_public_key, input_data)
    with open(out_filename, 'wb') as file:
      output = struct.pack(
          "!H{}sH{}s".format(len(encrypted_key), len(encrypted_data)),
          len(encrypted_key), encrypted_key,
          len(encrypted_data), encrypted_data
      )
      file.write(output)
  if action == 'decrypt':
    # deszyfrowanie pliku
    private_key=priv_key('test.key')
    with open(in_filename, 'rb') as file:
      data = file.read()
      (encrypted_key, encrypted_data)=unpack_data(data)
    decrypted_data = decrypt_data(private_key, encrypted_key, encrypted_data)
    with open(out_filename, 'wb') as file:
      file.write(decrypted_data)
