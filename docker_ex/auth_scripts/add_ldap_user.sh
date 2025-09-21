#!/bin/bash
# auth_scripts/add_ldap_user.sh

# --- Zmienne konfiguracyjne ---
LDAP_ADMIN_PASSWORD="adminpassword"
LDAP_BASE_DN="dc=example,dc=com"

# --- Dane nowego użytkownika ---
USERNAME="einstein"
FULL_NAME="Albert Einstein"
FIRST_NAME="Albert"
LAST_NAME="Einstein"
USER_PASSWORD="password123"
UID_NUMBER="1001"
GID_NUMBER="1001"
HOME_DIR="/home/${USERNAME}"

echo "Przygotowywanie do dodania użytkownika '${USERNAME}' do LDAP..."

# Generowanie hasła w formacie SSHA (Salted SHA)
HASHED_PASSWORD=$(slappasswd -h {SSHA} -s "$USER_PASSWORD")

# Tworzenie pliku LDIF dla nowego użytkownika
cat > /tmp/user_${USERNAME}.ldif <<EOF
dn: uid=${USERNAME},ou=people,${LDAP_BASE_DN}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
cn: ${FULL_NAME}
sn: ${LAST_NAME}
givenName: ${FIRST_NAME}
uid: ${USERNAME}
uidNumber: ${UID_NUMBER}
gidNumber: ${GID_NUMBER}
homeDirectory: ${HOME_DIR}
loginShell: /bin/bash
userPassword: ${HASHED_PASSWORD}
EOF

# Dodawanie użytkownika do LDAP
echo "Dodawanie użytkownika '${USERNAME}'..."
ldapadd -x -D "cn=admin,${LDAP_BASE_DN}" -w "$LDAP_ADMIN_PASSWORD" -f /tmp/user_${USERNAME}.ldif

if [ $? -eq 0 ]; then
    echo "SUKCES: Użytkownik '${USERNAME}' został dodany do LDAP."
    echo "   - Hasło: ${USER_PASSWORD}"
else
    echo "BŁĄD: Nie udało się dodać użytkownika. Sprawdź, czy serwer LDAP działa i czy hasło administratora jest poprawne."
fi

# Czyszczenie
rm /tmp/user_${USERNAME}.ldif