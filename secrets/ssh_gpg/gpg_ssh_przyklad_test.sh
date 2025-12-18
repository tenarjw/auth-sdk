#!/bin/bash

sudo apt install gnupg gpg-agent gnupg2
# Generowanie głównego klucza (signing)
gpg --quick-gen-key "jurek <jurek@example.com>" ed25519 sign 2y
# Pobranie odcisku palca nowo utworzonego klucza
fpr=$(gpg --list-secret-keys --with-colons "jurek <jurek@example.com>" | awk -F: '/^fpr/ {print $10; exit}')
# Dodanie subklucza (encryption) używając odcisku
gpg --quick-add-key "$fpr" cv25519 encr 2y
echo "sprawdź czy masz klucz do podpisu i szufrowania: [SC] i [E]"
gpg --list-keys jurek
#---------------
# Zainicjowanie pliku z hasłami:
./gpg_ssh.py -i
# dodanie hasła do certyfikatu ~/.ssh/certyfikat1
./gpg_ssh.py -a certyfikat1 -p hasło1
# pobranie  z pliku haseł i dodanie do ssh_agent:
./gpg_ssh.py
