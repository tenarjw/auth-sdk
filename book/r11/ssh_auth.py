#!/usr/bin/env python3
import paramiko
import getpass
import os

hostname = '10.0.0.220'
port = 22
username = 'api'
key_filepath = os.path.expanduser('~/.ssh/server3') # Użyj pełnej ścieżki do klucza

if __name__ == "__main__":
    client = paramiko.SSHClient()

    # Krok 1: Załaduj systemowe klucze hostów z ~/.ssh/known_hosts
    # To kluczowy krok dla bezpiecznej weryfikacji serwera!
    client.load_system_host_keys()
    
    # Domyślnie Paramiko używa RejectPolicy - odrzuci nieznane hosty.

    try:
        # Pytaj o hasło, jeśli klucz prywatny jest nim chroniony
        key_password = getpass.getpass(f'Passphrase for private key ({key_filepath}): ')

        # Krok 2: Połącz się, używając klucza prywatnego
        client.connect(
            hostname,
            port,
            username,
            key_filename=key_filepath,
            passphrase=key_password if key_password else None
        )
        
        # Krok 3: Wykonaj polecenie
        stdin, stdout, stderr = client.exec_command('df -h')
        print(stdout.read().decode())

    except paramiko.ssh_exception.SSHException as e:
        print(f"Błąd bezpieczeństwa lub połączenia: {e}")
        print(f"Wskazówka: Upewnij się, że klucz hosta dla '{hostname}' jest w pliku ~/.ssh/known_hosts.")
    except FileNotFoundError:
        print(f"Błąd: Plik klucza prywatnego nie został znaleziony w '{key_filepath}'")
    except Exception as e:
        print(f"Wystąpił nieoczekiwany błąd: {e}")
    finally:
        client.close()
