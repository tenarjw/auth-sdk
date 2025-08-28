#!/bin/bash

GROUP_NAME="xsecure"
VPATH=$(pwd)/xsecure
USER=$1

sudo usermod -aG $GROUP_NAME $USER

cd $VPATH
mkdir $USER
mkdir $USER/priv
mkdir $USER/xzip
chown $USER:$GROUP_NAME $USER
chown -R $USER:$USER $USER/priv
chown -R $USER:$USER $USER/xzip
chmod 700 $USER/priv
chmod 700 $USER/xzip
exit 0
