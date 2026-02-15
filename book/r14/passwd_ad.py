#!/usr/bin/env python3
from ldap3 import Connection, Server, MODIFY_REPLACE, Tls, ALL
import ssl

# Konfiguracja
SERVER_ADDR = 'ad.firma.local'
BIND_DN = 'CN=admin,CN=Users,DC=firma,DC=local'
BIND_PASS = 'SuperTajneHasloAdmina'  # W produkcji użyj zmiennych środowiskowych
CA_CERTS_FILE = '/path/to/ad_ca.cer'  # Certyfikat CA domeny

# Dane do zmiany
target_user_dn = 'CN=Anna Nowak,OU=Users,DC=firma,DC=local'
new_password = 'NoweSilneHaslo123!'

# Konfiguracja TLS
tls_config = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=CA_CERTS_FILE)

try:
    # Połączenie LDAPS (port 636)
    server = Server(SERVER_ADDR, port=636, use_ssl=True, get_info=ALL, tls=tls_config)
    
    with Connection(server, user=BIND_DN, password=BIND_PASS, raise_exceptions=True) as conn:
        print("Połączono z serwerem AD.")
        
        # Reset hasła (wymaga uprawnień)
        conn.modify(target_user_dn, {'unicodePwd': [(MODIFY_REPLACE, [new_password])]})
        print(f"Pomyślnie zresetowano hasło dla użytkownika: {target_user_dn}")
        
        # Opcjonalnie: wymuś zmianę hasła przy następnym logowaniu
        conn.modify(target_user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
        print("Ustawiono flagę wymuszenia zmiany hasła przy następnym logowaniu.")

except Exception as e:
    print(f"Wystąpił błąd: {e}")
