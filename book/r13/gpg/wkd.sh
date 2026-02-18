# Apache
WEBROOT=/var/www/html
mkdir -p $WEBROOT/.well-known/openpgpkey/hu
echo '<IfModule mod_mime.c>\nForceType application/pgp-key\n</IfModule>' > $WEBROOT/.well-known/openpgpkey/hu/.htaccess
chmod 0644 $WEBROOT/.well-known/openpgpkey/hu/.htaccess

# export
gpg --with-wkd-hash --fingerprint jurek@example.com
gpg --no-armor --export A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4 > $WEBROOT/.well-known/openpgpkey/hu/<wkd-hash>
chmod 0644 $WEBROOT/.well-known/openpgpkey/hu/<wkd-hash>

# policy
touch $WEBROOT/.well-known/openpgpkey/policy
chmod 0644 $WEBROOT/.well-known/openpgpkey/policy


#