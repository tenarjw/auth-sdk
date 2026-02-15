#!/usr/bin/python3
# -*- coding: utf-8 -*-
import pickle
import time
import samba.param
from samba.samdb import SamDB
from samba.auth import system_session
import ldap  # Wymaga instalacji: pip install python-ldap
import logging

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

pickleFN = 'cUSN.pickle'
SLEEP_TIME = 10
smb_conf = '/etc/samba/smb.conf'
base = "CN=Users,DC=firma,DC=pl"

lp = samba.param.LoadParm()
lp.load(smb_conf)

def sync(fromUSN):
    try:
        sam = SamDB(lp=lp, session_info=system_session())
        uSN = int(fromUSN)
        # Zoptymalizowany filtr LDAP dla większej precyzji
        filter = '(&(objectCategory=person)(objectClass=user)(|(uSNChanged>=%s)(uSNCreated>=%s)))' % (uSN, uSN)
        res = sam.search(base=base,
                         expression=filter,
                         attrs=['description', 'sAMAccountName', 'displayName', 'givenName',
                                'uSNCreated', 'uSNChanged', 'unicodePwd'])
        if not res:
            logging.info("Brak zmian do synchronizacji dla uSN >= %s", uSN)
            return uSN

        # Przykład replikacji do OpenLDAP
        ldap_conn = ldap.initialize('ldaps://openldap.firma.pl')
        ldap_conn.simple_bind_s('cn=admin,dc=firma,dc=pl', 'LdapAdminPass123!')
        for entry in res:
            dn = str(entry['dn'])
            sAMAccountName = str(entry.get('sAMAccountName', ''))
            displayName = str(entry.get('displayName', ''))
            # Przykład: aktualizacja wpisu w OpenLDAP
            ldap_conn.modify_s(f"cn={sAMAccountName},ou=Users,dc=firma,dc=pl",
                              [(ldap.MOD_REPLACE, 'displayName', displayName.encode('utf-8'))])
            logging.info("Zsynchronizowano użytkownika: %s", sAMAccountName)

        # Znajdź maksymalny USN dla następnego cyklu
        max_usn = max(int(entry.get('uSNChanged', uSN)) for entry in res)
        ldap_conn.unbind_s()
        return max_usn + 1

    except Exception as e:
        logging.error("Błąd synchronizacji: %s", e)
        return uSN

# Pętla główna z obsługą błędów
def main():
    try:
        with open(pickleFN, 'rb') as f:
            last_usn = pickle.load(f)
    except FileNotFoundError:
        last_usn = 0

    while True:
        try:
            new_usn = sync(last_usn)
            if new_usn != last_usn:
                with open(pickleFN, 'wb') as f:
                    pickle.dump(new_usn, f)
                last_usn = new_usn
            time.sleep(SLEEP_TIME)
        except Exception as e:
            logging.error("Błąd w pętli głównej: %s", e)
            time.sleep(SLEEP_TIME * 2)  # Retry z opóźnieniem

if __name__ == "__main__":
    main()
