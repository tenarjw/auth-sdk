#!/bin/bash

HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybor opcji"
TITLE="Operacje"
MENU="Wybierz menu:"

OPTIONS=(0 "Informacje o sambie"
         1 "Dodanie uzytkownika nowy"
         2 "Test grup"
         3 "Test ssh"
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
        2) /examples/test_group.sh
           ;;
        3) /examples/test_ssh.sh
           ;;
        9)
            /bin/bash
            ;;
esac
echo "Naciśnij Enter"
read e
/examples/menu.sh