   #!/usr/bin/env python3
   import paramiko
   import getpass
   import socket
   import sys
   import traceback

   hostname = 'serwer.firma.pl'
   username = 'admin'
   port = 22

   try:
       client = paramiko.SSHClient()
       client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
       client.load_system_host_keys()
       hostname = socket.getfqdn(hostname)
       client.connect(hostname, port, username, gss_auth=True, gss_kex=True, gss_deleg_creds=True)
       print("Połączono pomyślnie. Uruchamianie powłoki...")
       chan = client.invoke_shell()
       print(f"Transport: {repr(client.get_transport())}")
       # Uproszczona powłoka interaktywna; w produkcji użyj własnej logiki
       while True:
           data = chan.recv(1024).decode('utf-8')
           if not data:
               break
           print(data, end='')
       chan.close()
       client.close()

   except paramiko.AuthenticationException:
       password = getpass.getpass(f"Uwierzytelnianie GSSAPI nie powiodło się. Podaj hasło dla {username}@{hostname}: ")
       client.connect(hostname, port, username, password)
       print("Połączono za pomocą hasła. Uruchamianie powłoki...")
       chan = client.invoke_shell()
       while True:
           data = chan.recv(1024).decode('utf-8')
           if not data:
               break
           print(data, end='')
       chan.close()
       client.close()

   except Exception as e:
       print(f"Wyjątek: {e.__class__.__name__}: {e}")
       traceback.print_exc()
       try:
           client.close()
       except:
           pass
       sys.exit(1)
