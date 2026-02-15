#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# UWAGA: Ten skrypt wymaga instalacji biblioteki pycryptodomex
# Uruchom: pip install pycryptodomex

import base64
import binascii
from Cryptodome.Hash import MD4

try:
    password = input('Podaj hasło do testu: ')
    
    # AD wymaga hasła w cudzysłowach zakodowanego w UTF-16LE podczas ustawiania
    quoted_password = f'"{password}"'
    hash_md4 = MD4.new(quoted_password.encode('utf-16le')).digest()
    
    # Format dla OpenLDAP (sambaNTPassword) - heksadecymalny hash NT
    samba_nt_password = binascii.hexlify(hash_md4).decode('ascii').upper()
    print(f"sambaNTPassword (NT Hash): {samba_nt_password}")
    
    # Format dla AD (unicodePwd) - hash NT w Base64
    unicode_pwd = base64.b64encode(hash_md4).decode('ascii')
    print(f"unicodePwd (Base64 NT Hash): {unicode_pwd}")

except ImportError:
    print("\nBŁĄD: Biblioteka pycryptodomex nie jest zainstalowana.")
    print("Aby uruchomić ten skrypt, wykonaj polecenie:")
    print("pip install pycryptodomex")
except Exception as e:
    print(f"Wystąpił błąd: {e}")
