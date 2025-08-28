#!/bin/bash

GROUP_NAME="xsecure"
VPATH=$(pwd)/xsecure
USER1=$1
USER2=$2

sudo mkdir -p $VPATH/$USER1/$USER2/out
sudo mkdir -p $VPATH/$USER2/$USER1/out


exit 0
