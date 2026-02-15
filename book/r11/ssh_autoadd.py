# ... importy ...

client = paramiko.SSHClient()
client.load_system_host_keys()

# Ustaw politykę automatycznego dodawania nieznanych kluczy hosta.
# OSTRZEŻENIE: Niebezpieczne w środowiskach produkcyjnych! Używaj tylko w zaufanych sieciach.
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# ... reszta kodu (connect, exec_command) ...
