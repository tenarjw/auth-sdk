#!/bin/bash

sudo -E docker run --rm \
-v "$(pwd)/xsecure/dell:/app/dell" \
-v "$(pwd)/xsecure/jurek:/app/jurek" \
--env ACTION=RECEIVE \
--env USERNAME=jurek \
--env MYNAME=dell \
 xsecure 


exit 0

