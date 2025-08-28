#!/bin/bash

sudo ./xuser.sh jurek
sudo ./xuser.sh dell
sudo ./xcommon.sh jurek dell


sudo -E docker run --rm \
-v "$(pwd)/xsecure/dell:/app/dell" \
-v "$(pwd)/xsecure/jurek:/app/jurek" \
--env ACTION=DH \
--env USERNAME=dell \
--env MYNAME=jurek \
 xsecure 

sudo -E docker run --rm \
-v "$(pwd)/xsecure/dell:/app/dell" \
-v "$(pwd)/xsecure/jurek:/app/jurek" \
--env ACTION=KEYS \
--env USERNAME=dell \
--env MYNAME=jurek \
 xsecure 

sudo -E docker run --rm \
-v "$(pwd)/xsecure/dell:/app/dell" \
-v "$(pwd)/xsecure/jurek:/app/jurek" \
--env ACTION=KEYS \
--env USERNAME=jurek  \
--env MYNAME=dell \
 xsecure 






exit 0

