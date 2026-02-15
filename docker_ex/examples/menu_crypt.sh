#!/bin/bash

HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybór opcji"
TITLE="Kryptografia"
MENU="Wybierz przykład:"

OPTIONS=(0 "powrót do głównego menu"
         1 "Z biblioteki Fernet"
         2 "AES-GCM"
         3 "SHA256"
         4 "SHA256 z solą"
         5 "MD5"
         6 "Z bibliteki bcrypt"
         7 "Przykład: szyfrowanie pliku"
         )

CHOICE=$(dialog --clear \
                --backtitle "$BACKTITLE" \
                --title "$TITLE" \
                --menu "$MENU" \
                $HEIGHT $WIDTH $CHOICE_HEIGHT \
                "${OPTIONS[@]}" \
                2>&1 >/dev/tty)

clear
if [[ ! "$CHOICE" =~ ^[0-9]+$ ]]; then
    echo "Nieprawidłowy wybór" >&2
    exit 1
fi
case $CHOICE in
        0)
            ./menu.sh
            ;;
        1)
            python p16_crypt_fernet.py
            ;;
        2)
            python p17_AES_GCM.py
            ;;
        3)
            python p23_sha256.py
            ;;
        4)
            python p24_sha256salt.py
            ;;
        5)
            python p27_MD5.py
            ;;
        6)
            python p28_bcrypt.py
            ;;
        7)
            ./test_fcrypt.sh 
            ;;
esac
echo "Naciśnij Enter"
read e

