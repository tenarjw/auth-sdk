#!/bin/bash

KEY="example"
KEYPATH="$HOME/.ssh/$KEY"
CERT="$HOME/.ssh/$KEY.pub"
USER=administrator
INI=$1
PRIVATE_NET=10.0.0.0/8
PRIVATE_HOST=10.0.0.13
TUN=tun0
HEIGHT=25
WIDTH=40
CHOICE_HEIGHT=15
BACKTITLE="Wybór opcji"
TITLE="Serwery"
MENU="Wybierz serwer:"

OPTIONS=(0 "następna strona"
         1 "listuj pamięć ssh"
         2 "serwer 1"
         3 "poczta - statystyka"
         )

if ip address show  tun0 | grep -q "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00"
then
   if ping -c 1 $PRIVATE_HOST &> /dev/null
   then
     echo "siec dostępna"
   else
     echo "ustawiam trasę z sieci zdalnej"
     sudo ip route add $PRIVATE_NET dev $TUN
   fi
fi


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
            ./menu2.sh $INI
            ;;
        1)
            ./certs.sh;./menu.sh
            ;;
        2)
            ssh  -i ~/.ssh/admin  admin@10.0.0.232
            ;;
        3)
            ./ssh_mstat.sh ; ./menu.sh
            ;;
        *) 
           exit 0
           ;;
esac

if [  "-i" = "$INI" ];
then
  if [ ! -f "$CERT" ];  then
    ssh-keygen -t rsa -b 2048  -f $KEY
    mv $KEY*  ~/.ssh
    chmod 600 $KEYPATH
    chmod 600 $CERT
  fi
exit 0
