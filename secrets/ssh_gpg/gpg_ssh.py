#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import subprocess
import json
import argparse
import pexpect
from pathlib import Path

# --- KONFIGURACJA ---
RECIPIENT = "jurek@example.com"
GPG_BIN = 'gpg2'
PFILE = '.pass-store'
# --------------------

class CertsPasswordStore:
    def __init__(self, path=None):
        if path is None:
            self.store_path = Path.home() / PFILE
        else:
            self.store_path = Path(path).expanduser()
            
        self.passwords = []
        
        if self.store_path.exists():
            self.decrypt_passwords()

    def add_password(self, ident, password):
        # Sprawdzamy, czy identyfikator już istnieje, jeśli tak - aktualizujemy
        self.passwords = [p for p in self.passwords if p['cert'] != ident]
        self.passwords.append({'cert': ident, 'password': password})

    def encrypt_passwords(self):
        gpg = subprocess.Popen(
            [GPG_BIN, '-e', '--recipient', RECIPIENT, '--batch', '--yes', '-o', str(self.store_path)],
            stdin=subprocess.PIPE
        )
        gpg.stdin.write(json.dumps(self.passwords).encode())
        gpg.stdin.close()
        gpg.wait()
        if gpg.returncode != 0:
            raise Exception(f'Błąd szyfrowania pliku {self.store_path}')

    def decrypt_passwords(self):
        gpg = subprocess.Popen(
            [GPG_BIN, '--quiet', '--batch', '--decrypt'],
            stdin=open(self.store_path, 'rb'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = gpg.communicate()
        if gpg.returncode == 0:
            self.passwords = json.loads(stdout)
        else:
            raise Exception(f'Błąd deszyfrowania: {stderr.decode()}')

def add_to_ssh_agent(cert_name, password):
    """
    Używa pexpect do automatycznego wpisania hasła do ssh-add.
    """
    key_path = Path.home() / '.ssh' / cert_name
    
    if not key_path.exists():
        print(f"[-] Pomijam: Plik {key_path} nie istnieje.")
        return

    print(f"[*] Dodawanie klucza do agenta: {cert_name}")
    
    # Uruchomienie ssh-add dla konkretnego pliku
    child = pexpect.spawn(f'ssh-add {str(key_path)}')
    
    try:
        # Czekamy na prośbę o hasło (obsługa różnych wariantów językowych)
        index = child.expect(['Enter passphrase', 'Enter password', r'[Hh]as.o', 'passphrase'], timeout=5)
        child.sendline(password)
        child.expect(pexpect.EOF)
        
        # Sprawdzenie wyniku po wysłaniu hasła
        output = child.before.decode() if child.before else ""
        if "Identity added" in output or child.exitstatus == 0:
            print(f"[+] Sukces: {cert_name} dodany.")
        else:
            print(f"[!] Błąd przy dodawaniu {cert_name}: {output.strip()}")
            
    except pexpect.TIMEOUT:
        print(f"[?] Timeout: ssh-add nie poprosił o hasło dla {cert_name}. Może klucz nie ma hasła?")
    except pexpect.EOF:
        print(f"[+] Klucz {cert_name} został przetworzony (EOF).")


if __name__ == "__main__":
    usage = "Magazyn haseł SSH oparty na GPG"
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument('-i', '--init', help='Zainicjuj pusty magazyn', action="store_true")
    parser.add_argument('-a', '--add', help='Nazwa pliku klucza w ~/.ssh/')
    parser.add_argument('-p', '--password', help='Hasło do tego klucza')
    args = parser.parse_args()

    store = CertsPasswordStore()

    if args.init:
        store.encrypt_passwords()
        print(f"[+] Zainicjowano plik: {store.store_path}")
        
    elif args.add and args.password:
        store.add_password(args.add, args.password)
        store.encrypt_passwords()
        print(f"[+] Dodano hasło dla {args.add} i zaszyfrowano magazyn.")
        
    else:
        # Główny tryb: Odszyfruj i dodaj wszystko do agenta
        if not store.passwords:
            print("[-] Magazyn jest pusty lub nie istnieje.")
        else:
            for p in store.passwords:
                add_to_ssh_agent(p['cert'], p['password'])
