#!/usr/bin/env python
# -*- coding: utf8 -*-
from cryptography.fernet import Fernet

# 1. Wygeneruj klucz (zrób to tylko raz i przechowuj w bezpiecznym miejscu)
key = Fernet.generate_key()
print("Klucz (trzymaj w sekrecie!): %s" % key)

# Utwórz instancję Fernet z kluczem
f = Fernet(key)

# 2. Zaszyfruj dane
w="To jest moja super tajna wiadomość."
print(f'Testowa wiadomość: {w}')
p = w.encode("utf-8")

# Jawny tekst musi byc w bajtach, co zapewnia encode("utf-8") 
c = f.encrypt(p)
print("\nSzyfrogram: %s" % c)

# 3. Odszyfruj dane
p_odszyfrowany = f.decrypt(c)
print("\nOdszyfrowany tekst: %s" % p_odszyfrowany.decode('utf-8'))

print('\n\nPrzykład próby modyfikacji szyfrogramu:')
try:
    f.decrypt(c + b'zlosliwa_zmiana')
except Exception as e:
    print("\nBlad przy deszyfrowaniu! Szyfrogram zostal zmieniony. (%s)" % e)
