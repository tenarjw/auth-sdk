openssl passwd -6 -salt $(openssl rand -hex 8)

# alternatywa:
#PASSWORD=$1
#HASH=`echo $PASSWORD | openssl passwd -6 -salt $(openssl rand -hex 8)
#,
# -stdin`
#echo $HASH
