#!/bin/bash

HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybór opcji"
TITLE="Autoryzacja w systemie Linux"
MENU="Wybierz przykład:"

OPTIONS=(0 "powrót do głównego menu"
         1 "Inicjowanie LDAP (tylko raz!)"
         2 "Test LDAP"
         3 "test SSSD"
         4 "Przywróć standard"
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
            /auth_scripts/initialize_ldap_server.sh 
            /auth_scripts/add_ldap_user.sh 
            ;;
        2)
            /auth_scripts/test_ldap.sh 
            ;;
        3)
            /auth_scripts/test_sssd.sh 
            ;;
        4)
            /auth_scripts/test_std.sh 
            ;;
esac
echo "Naciśnij Enter"
read e

