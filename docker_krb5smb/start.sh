#!/bin/bash
set -euo pipefail
LOGFILE=/var/log/samba/provision.log
mkdir -p /var/log/samba
exec > >(tee -a "$LOGFILE") 2>&1

echo "==== start.sh: $(date -Is) ===="

echo "Tworzenie katalogów /var/lib/samba/sysvol i /var/lib/samba/private..."
mkdir -p /var/lib/samba/sysvol /var/lib/samba/private /srv/samba/share /home/EXAMPLE/administrator
chown -R root:root /var/lib/samba /srv/samba/share
chmod 755 /var/lib/samba
chmod 700 /var/lib/samba/private
chmod 770 /srv/samba/share || true

echo "Sprawdzanie wsparcia dla ACL..."
getfacl /var/lib/samba/sysvol || true

# DEBUG: pokaż zawartość katalogu private przed provisioningiem
echo "--- /var/lib/samba/private przed provisioningiem ---"
ls -la /var/lib/samba/private || true

# Jeśli brakuje bazy - spróbuj provision
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "Brak sam.ldb -> uruchamiam samba-tool domain provision"
    # Usuń stare dane, aby zapewnić czystą konfigurację
    rm -rf /var/lib/samba/private/*
    samba-tool domain provision \
        --use-rfc2307 \
        --realm=EXAMPLE.COM \
        --domain=EXAMPLE \
        --adminpass="TwojeHaslo123!" \
        --server-role=dc \
        --dns-backend=NONE \
        --debuglevel=5 || {
            echo "ERROR: samba-tool domain provision zwrócił błąd. Zawartość /var/log/samba/provision.log:"
            tail -n 200 "$LOGFILE" || true
            exit 1
        }
    # Naprawa błędu z DNS/smb4.example.com w secrets.ldb
    echo "Sprawdzanie i naprawa SPN dla DNS..."
    M="$(hostname -s)$"
    SPN="DNS/$(hostname -f)"
    # Sprawdź, czy SPN istnieje
    echo "Sprawdzanie istniejącego SPN: $SPN"
    ldbsearch -H /var/lib/samba/private/sam.ldb "(servicePrincipalName=$SPN)" | tee -a /var/log/samba/provision.log
    # Usuń istniejący SPN, jeśli jest
    echo "Usuwanie istniejącego SPN, jeśli istnieje..."
    samba-tool spn delete "$SPN" || {
        echo "Brak SPN $SPN do usunięcia lub błąd podczas usuwania (kontynuuję)."
    # Utwórz dowiązanie symboliczne do pliku keytab Samby,
    # aby sshd i inne usługi mogły z niego korzystać.
    ln -sf /var/lib/samba/private/secrets.keytab /etc/krb5.keytab        
    }
    # Dodaj nowy SPN
    echo "Dodawanie SPN: $SPN dla $M"
    samba-tool spn add "$SPN" "$M" || {
        echo "ERROR: samba-tool spn add zwrócił błąd!"
        exit 1
    }
    # Dodaj SPN dla SSH
    echo "Dodawanie SPN dla SSH: host/smb4.example.com@EXAMPLE.COM"
    samba-tool spn add "host/smb4.example.com@EXAMPLE.COM" "$M" || {
        echo "ERROR: samba-tool spn add dla host/smb4.example.com zwrócił błąd!"
        exit 1
    }
    # Eksport krb5.keytab zastępujemy linkiem z samby - poniżej
    # samba-tool domain exportkeytab /etc/krb5.keytab ....

    # Warunkowe ustawienie uprawnień TLS
    echo "Ustawianie uprawnień TLS..."
    if [ -d /var/lib/samba/private/tls ]; then
        chmod 700 /var/lib/samba/private/tls
        if ls /var/lib/samba/private/tls/*.pem >/dev/null 2>&1; then
            chmod 600 /var/lib/samba/private/tls/*.pem
            chown root:root /var/lib/samba/private/tls /var/lib/samba/private/tls/
        else
            echo "Brak plików .pem w /var/lib/samba/private/tls – pomijam chmod."
        fi
    else
        echo "Brak katalogu /var/lib/samba/private/tls – pomijam ustawianie uprawnień TLS."
    fi
    
    # Ustawienie grupy Domain Users na katalog domowy
    echo "Ustawianie grupy Domain Users na katalog domowy..."
    if wbinfo --ping-dc >/dev/null 2>&1; then
        chown root:"Domain Users" /home/EXAMPLE/administrator
        chmod 770 /home/EXAMPLE/administrator
        setfacl -m g:"Domain Users":rwx /home/EXAMPLE/administrator
    else
        echo "Ostrzeżenie: winbind nie działa – pomijam ustawienie grupy na katalog domowy."
    fi
else
    echo "Plik sam.ldb obecny — pomijam provisioning."
fi

# Po provisioning sprawdź pliki secrets
echo "--- sprawdzam pliki secrets ---"
for f in /var/lib/samba/private/secrets.ldb /var/lib/samba/private/secrets.tdb; do
    if [ -f "$f" ]; then
        echo "OK: $f istnieje:"
        ls -l "$f"
    else
        echo "BRAK: $f - to oznacza, że provisioning nie utworzył bazy sekretów poprawnie!"
    fi
done

# Wyświetl fragment bazy secrets
if [ -f /var/lib/samba/private/secrets.ldb ]; then
    echo "--- ldbsearch: primaryDomain (secrets.ldb) ---"
    ldbsearch -H /var/lib/samba/private/secrets.ldb "(objectclass=primaryDomain)" || true
    echo "--- ldbsearch: DNS/smb4.example.com (secrets.ldb) ---"
    ldbsearch -H /var/lib/samba/private/secrets.ldb "(servicePrincipalName=DNS/smb4.example.com)" || true
fi

# Wyświetl listę DB w private
echo "--- lista plików w /var/lib/samba/private ---"
ls -la /var/lib/samba/private

# Sprawdź krb5.keytab
# Ustawienie jednolitego pliku keytab dla całego systemu
ln -sf /var/lib/samba/private/secrets.keytab /etc/krb5.keytab
chown root:root /etc/krb5.keytab
chmod 600 /etc/krb5.keytab
# Debug keytab
echo "Zawartość krb5.keytab:"
klist -k /etc/krb5.keytab || true

# Debug Winbind/NSS mapping
echo "--- Sprawdzanie mapowania użytkowników Winbind/NSS ---"
wbinfo -n Administrator || echo "Błąd: wbinfo -n Administrator nie powiodło się"
getent passwd administrator || echo "Błąd: getent passwd administrator nie powiodło się"
wbinfo -u || echo "Błąd: wbinfo -u nie powiodło się"
getent passwd || echo "Błąd: getent passwd nie powiodło się"

# Ustawienie uprawnień dla grupy Domain Users na share (opcjonalnie)
if wbinfo --ping-dc >/dev/null 2>&1; then
    echo "winbind w sambie działa – ustawiam ACL na share"
    chown root:"Domain Users" /srv/samba/share
    chmod 770 /srv/samba/share
    setfacl -m g:"Domain Users":rwx /srv/samba/share
else
    echo "Ostrzeżenie: wbudowany winbind może jeszcze się uruchamiać – pomijam ACL na share."
fi

# Uruchomienie supervisord
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf