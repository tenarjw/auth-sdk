#!/bin/bash

HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybór opcji"
TITLE="Algorytmy"
MENU="Wybierz przykład:"

OPTIONS=(0 "powrót do głównego menu"
         1 "Protokół Diffiego-Hellmana"
         2 "Algorytm RSA"
         3 "Protokół Needhama-Schroedera"
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
            python p44_DH.py
            ;;
        2)
            python p45_RSA.py
            ;;
        3)
            python p47_NS.py
            ;;
esac
echo "Naciśnij Enter"
read e
