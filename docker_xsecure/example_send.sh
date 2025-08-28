#!/bin/bash

sudo -E docker run --rm \
-v "$(pwd)/xsecure/dell:/app/dell" \
-v "$(pwd)/xsecure/jurek:/app/jurek" \
--env ACTION=SEND \
--env USERNAME=dell \
--env MYNAME=jurek \
 xsecure 


exit 0

