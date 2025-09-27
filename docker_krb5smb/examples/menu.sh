#!/bin/bash

HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybor opcji"
TITLE="Operacje"
MENU="Wybierz menu:"

OPTIONS=(0 "Informacje (czy KDC gotowy?)"
         1 "Dodanie uzytkownika nowy"
         2 "Test KBC/kinit"
         3 "Test ssh"
         4 "Test smbclient"
         9 "bash"
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
        0) /examples/smb_info.sh
           ;;
        1) /examples/test_user.sh
           ;;
        2) /examples/test_kinit.sh
           ;;
        3) /examples/test_ssh.sh
           ;;
        4) /examples/p222_smbclient.sh
           ;;
        9)
            /bin/bash
            ;;
esac
echo "Naciśnij Enter"
read e
/examples/menu.sh