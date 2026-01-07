#!/bin/bash
set -e

# Sprawdź wymagane zmienne
: "${RELAY_HOST:?Missing RELAY_HOST}"
: "${RELAY_PORT:?Missing RELAY_PORT}"
: "${RELAY_USER:?Missing RELAY_USER}"
: "${RELAY_PASS:?Missing RELAY_PASS}"
: "${DOMAIN:?Missing DOMAIN}"
: "${LETSENCRYPT_EMAIL:?Missing LETSENCRYPT_EMAIL}"

#  CONFIGURE HOSTNAME
if [ -z "${HOSTNAME}" ]; then
  echo "ERROR: HOSTNAME environment variable is not set."
  echo "Please run the container with -e HOSTNAME=mail.yourdomain.com"
  exit 1
fi
echo "${HOSTNAME}" > /etc/mailname
echo "127.0.0.1 ${HOSTNAME}" >> /etc/hosts


# CLEANUP STALE FILES
rm -f /var/run/clamav/clamd.ctl
rm -f /var/run/spamd.pid

# Przetworzenie konfiguracji
envsubst < /etc/postfix/main.cf.template > /etc/postfix/main.cf
envsubst < /etc/opendkim.conf > /etc/opendkim.conf.tmp && mv /etc/opendkim.conf.tmp /etc/opendkim.conf

# NAPRAWA UPRAWNIEŃ 
chown root:root /etc/postfix/main.cf /etc/postfix/master.cf
chmod 644 /etc/postfix/main.cf /etc/postfix/master.cf
# Unikamy postfix set-permissions, który sypie błędami w wersji slim


postfix check

# KONFIGURACJA DKIM
mkdir -p /etc/opendkim/keys
echo "127.0.0.1" > /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo "${DOMAIN}" >> /etc/opendkim/TrustedHosts

if [ ! -f "/etc/opendkim/keys/default.private" ]; then
    echo "Generowanie kluczy DKIM dla ${DOMAIN}..."
    opendkim-genkey -s default -d "${DOMAIN}" -D /etc/opendkim/keys/
    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 /etc/opendkim/keys/default.private
    
    echo "--------------------------------------------------"
    echo "REKORD DNS DKIM (dodaj jako TXT dla default._domainkey):"
    cat /etc/opendkim/keys/default.txt
    echo "--------------------------------------------------"
fi

# Pozostała konfiguracja (SASL, certyfikaty)
if [ ! -f /etc/postfix/sasl_passwd ]; then
    echo "[${RELAY_HOST}]:${RELAY_PORT} ${RELAY_USER}:${RELAY_PASS}" > /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd*
fi

# transport / przekierowanie
echo "${DOMAIN} smtp:${FINAL_HOST_MX}" > /etc/postfix/transport
postmap /etc/postfix/transport

# Usunięcie starych plików PID
rm -f /var/run/opendkim/opendkim.pid /var/spool/postfix/pid/master.pid
rm -f /var/run/amavis/amavisd.pid

# Naprawa uprawnień dla Amavis
mkdir -p /var/lib/amavis/tmp /var/lib/amavis/db /var/run/amavis
chown -R amavis:amavis /var/lib/amavis /var/run/amavis

# Utwórz brakujące katalogi Postfix
postfix set-permissions || true
#postfix-post-install create-missing


# Ustawienie FQDN dla Amavis
echo "\$myhostname = '${HOSTNAME}';" > /etc/amavis/conf.d/05-node_id

# Aktualizacja baz ClamAV i SpamAssassin przy starcie
freshclam || true
sa-update || true

# Certyfikat Let's Encrypt
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ "${TEST_MODE}" != "true" ]; then
    if [ ! -f "${CERT_DIR}/fullchain.pem" ]; then
        echo "Obtaining Let's Encrypt certificate..."
        certbot certonly --standalone --non-interactive --agree-tos \
            --email "${LETSENCRYPT_EMAIL}" -d "${DOMAIN}" --http-01-port 80
    else
        echo "Certificates exist, will be renewed automatically via cron."
    fi
else
    echo "TEST_MODE enabled, skipping Let's Encrypt certificate generation."
fi

# Zainstaluj crontab
crontab /etc/cron.d/certbot-renew

# Wymuszenie FQDN dla Amavis
echo "\$myhostname = '${HOSTNAME}';" > /etc/amavis/conf.d/05-node_id
chown amavis:amavis /etc/amavis/conf.d/05-node_id
# Plik musi należeć do root, nie do amavis
chown root:root /etc/amavis/conf.d/05-node_id
chmod 644 /etc/amavis/conf.d/05-node_id

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf