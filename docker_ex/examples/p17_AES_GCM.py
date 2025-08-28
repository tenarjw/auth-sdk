#!/usr/bin/env python
# -*- coding: utf8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from binascii import hexlify as hexa
from os import urandom

# 1. Wybierz losowy klucz 16-bajtowy
key = urandom(16)
print("key = %s" % hexa(key).decode('ascii'))

# 2. Przygotuj dane jawne
p = "To jest moja super tajna wiadomość.".encode("utf-8") 
# Jawny tekst musi byc w bajtach - dlatego .encode("utf-8")

# --- SZYFROWANIE ---
# 3. Wygeneruj jednorazowy nonce 
# Standardowy rozmiar nonce dla GCM to 12 bajtów, 
# # co zapewnia optymalne bezpieczeństwo.
nonce = urandom(12)
print("nonce = %s" % hexa(nonce).decode('ascii'))

# 4. Utwórz szyfr AES-GCM
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
aes_encrypt = cipher.encryptor()

# 5. Zaszyfruj dane
c = aes_encrypt.update(p) + aes_encrypt.finalize()

# 6. Pobierz tag uwierzytelniający 
# Tag uwierzytelniający (MAC) weryfikuje integralność i autentyczność danych, 
# zapobiegając ich modyfikacji.
# Dlatego jest to kluczowy element GCM!
tag = aes_encrypt.tag
print("tag = %s" % hexa(tag).decode('ascii'))
print("enc(%s) = %s" % (p.decode('utf-8'), hexa(c).decode('ascii')))

# --- DESZYFROWANIE ---
# 7. Utwórz szyfr do deszyfrowania, podając nonce ORAZ tag
decrypt_cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
aes_decrypt = decrypt_cipher.decryptor()

# 8. Odszyfruj i zweryfikuj
try:
    p_odszyfrowany = aes_decrypt.update(c) + aes_decrypt.finalize()
    print("dec(%s) = %s" % (hexa(c).decode('ascii'), p_odszyfrowany.decode("utf-8") ))
    print("Weryfikacja udana!")
except InvalidTag:
    print("Weryfikacja nieudana! Szyfrogram został zmodyfikowany.")
