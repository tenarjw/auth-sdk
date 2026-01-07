#!/bin/bash
#
# scripts/update-certs.sh
# Odnawia certyfikat Let's Encrypt i przeładowuje usługi
#

set -euo pipefail

DOMAIN="${DOMAIN:-}"
EMAIL="${LETSENCRYPT_EMAIL:-}"

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
  echo "Brak wymaganych zmiennych środowiskowych: DOMAIN lub LETSENCRYPT_EMAIL" | tee -a /var/log/certbot.log
  exit 1
fi

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

echo "=== Rozpoczynam odnowienie certyfikatu dla ${DOMAIN} ===" | tee -a /var/log/certbot.log
certbot renew --quiet --deploy-hook "
  echo 'Certyfikat odnowiony, przeładowuję usługi...' | tee -a /var/log/certbot.log
  postfix reload >> /var/log/postfix-reload.log 2>&1 || echo 'Postfix reload failed' >> /var/log/mail.log
  systemctl reload amavis >> /var/log/amavis-reload.log 2>&1 || /usr/sbin/amavisd-new reload >> /var/log/amavis-reload.log 2>&1 || echo 'Amavis reload failed' >> /var/log/mail.log
"

# Opcjonalna weryfikacja daty ważności
if [[ -f "${CERT_DIR}/fullchain.pem" ]]; then
    EXPIRY_DATE=$(openssl x509 -enddate -noout -in "${CERT_DIR}/fullchain.pem" | cut -d= -f2)
    echo "Aktualny certyfikat ważny do: ${EXPIRY_DATE}" | tee -a /var/log/certbot.log
else
    echo "UWAGA: Nie znaleziono pliku fullchain.pem po odnowieniu" | tee -a /var/log/certbot.log
fi

echo "=== Zakończono aktualizację certyfikatu ===" | tee -a /var/log/certbot.log