#!/usr/bin/env python3
import ldap

def login(uid, password):
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    ldap_conn = ldap.initialize('ldaps://127.0.0.1:636')
    try:
        ldap_conn.simple_bind_s(f"uid={uid},ou=Users,dc=firma,dc=pl", password)
        ldap_conn.unbind()
        return True
    except ldap.LDAPError as e:
        print(f"LOGIN ERROR: {e}")
        return False

if login('test', 'hasło'):
    print('Logowanie udane')
