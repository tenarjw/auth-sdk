#!/usr/bin/env python3
import time
import hashlib
import binascii
from passlib.hash import ldap_md5_crypt
import ldap
import ldap.modlist as modlist

SHADOWMAX = 365*3600*24  # 365 days

class TLdap:
    def __init__(self, debug=False):
        self.bind_dn = "cn=admin,dc=firma,dc=pl"
        self.password = "Hasło"
        self.baseDN = "dc=firma,dc=pl"
        self.userDN = "uid=%s,ou=Users,dc=firma,dc=pl"
        self.uri = 'ldaps://10.0.0.217'
        self.debug = debug
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            self.ldap = ldap.initialize(self.uri)
        except ldap.LDAPError as e:
            if self.debug:
                print(f"Error: {e}")
            self.ldap = None

    def unbind(self):
        if self.ldap:
            self.ldap.unbind()

    def get_user_attr(self, uid):
        searchFilter = f'uid={uid}'
        searchScope = ldap.SCOPE_SUBTREE
        retrieveAttributes = [
            'userPassword', 'shadowLastChange', 'shadowExpire',
            'sambaNTPassword', 'sambaPwdLastSet', 'sambaPwdMustChange', 'sambaPwdCanChange'
        ]
        try:
            self.ldap.simple_bind(self.bind_dn, self.password)
            result = self.ldap.search_s(self.baseDN, searchScope, searchFilter, retrieveAttributes)
            if result:
                return result[0][1]
        except ldap.LDAPError as e:
            if self.debug:
                print(f"Error: {e}")
        return None

    def set_password(self, uid, password):
        userPassword = ldap_md5_crypt.encrypt(password)
        sambaNTPassword = binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest()).decode()
        rightNow = int(time.time())
        shadowLastChange = str(rightNow // (3600 * 24))
        shadowExpire = str(SHADOWMAX + rightNow)
        sambaPwdLastSet = str(rightNow)
        sambaPwdCanChange = '0'
        sambaPwdMustChange = str(SHADOWMAX + rightNow)
        old = self.get_user_attr(uid)
        new = {
            'userPassword': [userPassword.encode()],
            'shadowLastChange': [shadowLastChange.encode()],
            'shadowExpire': [shadowExpire.encode()],
            'sambaNTPassword': [sambaNTPassword.encode()],
            'sambaPwdLastSet': [sambaPwdLastSet.encode()],
            'sambaPwdMustChange': [sambaPwdMustChange.encode()],
            'sambaPwdCanChange': [sambaPwdCanChange.encode()]
        }
        dn = self.userDN % uid
        try:
            ldif = modlist.modifyModlist(old, new)
            self.ldap.modify_s(dn, ldif)
            return "password updated successfully"
        except Exception as e:
            if self.debug:
                print(f"Error: {e}")
            return "Fail - internal error"

def main():
    import sys
    if len(sys.argv) != 2:
        print('Użycie: ./setPassword.py <uid>')
    else:
        password = input('Podaj nowe hasło: ')
        password2 = input('Powtórz hasło: ')
        if password == password2:
            l = TLdap(True)
            print(l.set_password(sys.argv[1], password))
            l.unbind()
        else:
            print("Hasła się różnią")

if __name__ == "__main__":
    main()
