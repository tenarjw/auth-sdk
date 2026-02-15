# Ustawienie nazwy hosta
hostnamectl set-hostname adserwer

# Provisioning domeny
samba-tool domain provision --server-role='domain controller' \
          --dns-backend=SAMBA_INTERNAL \
          --realm=O.FIRMA.PL \
          --domain=ADOMENA \
          --adminpass=BardzoSilneHaslo123! \
          --use-rfc2307
