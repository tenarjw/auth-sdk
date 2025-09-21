#!/bin/bash
# auth_scripts/test_auth.sh

if [ -z "$1" ]; then
  echo "Użycie: $0 <nazwa_użytkownika>"
  exit 1
fi

USERNAME=$1

echo "Testowanie pobierania informacji dla użytkownika: $USERNAME"

# getent odpytuje bazy danych skonfigurowane w /etc/nsswitch.conf
if getent passwd "$USERNAME" > /dev/null; then
  echo "SUKCES: Znaleziono użytkownika '$USERNAME'."
  echo "---"
  getent passwd "$USERNAME"
  echo "---"
else
  echo "BŁĄD: Nie znaleziono użytkownika '$USERNAME'."
fi