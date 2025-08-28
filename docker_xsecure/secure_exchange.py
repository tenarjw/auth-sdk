import os
import shutil
import pwd
import grp
import stat
import base64
from datetime import datetime

import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives._serialization import Encoding, ParameterFormat, PrivateFormat, PublicFormat, \
  NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_parameters, load_pem_public_key, load_pem_private_key


def generate_dh_par(params_path):
  """Generuje parametry DH (jeśli nie istnieją)"""
  if not os.path.exists(params_path):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    with open(params_path, 'wb') as f:
      f.write(parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3))


def generate_dh_keys(params_path, priv_key_path, pub_key_path):
  """Generuje parametry DH (jeśli nie istnieją) oraz parę kluczy użytkownika."""
  # Krok 1: Wygeneruj i zapisz wspólne parametry, jeśli to pierwszy użytkownik
  if not os.path.exists(params_path):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    with open(params_path, 'wb') as f:
      f.write(parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3))
  else:
    with open(params_path, 'rb') as f:
      parameters = load_pem_parameters(f.read())

  # Krok 2: Wygeneruj klucze dla bieżącego użytkownika
  private_key = parameters.generate_private_key()
  public_key = private_key.public_key()

  with open(priv_key_path, 'wb') as f:
    f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
  with open(pub_key_path, 'wb') as f:
    f.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

  return private_key

def derive_password_from_keys(private_key, peer_public_key_path):
  """Generuje hasło na podstawie klucza prywatnego i publicznego drugiej strony."""
  with open(peer_public_key_path, 'rb') as f:
    peer_public_key = load_pem_public_key(f.read())

  # Wygeneruj wspólny sekret
  shared_key = private_key.exchange(peer_public_key)

  # Użyj HKDF do stworzenia bezpiecznego, 16-znakowego hasła
  hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'zip-password')
  password_bytes = hkdf.derive(shared_key)
  password = base64.b64encode(password_bytes).decode('utf-8')[:16]

  return password

def encrypt_zip(source_path, dest_path, password):
  """Szyfruje plik ZIP podanym hasłem."""
  with pyzipper.AESZipFile(dest_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
    zf.setpassword(password.encode('utf-8'))
    for root, _, files in os.walk(source_path):
      for file in files:
        file_path = os.path.join(root, file)
        # Ścieżka relatywna w archiwum (relative to source_folder)
        arcname = os.path.relpath(file_path, source_path)
        zf.write(file_path, arcname)

def decrypt_zip(source_path, dest_dir, password):
  """Deszyfruje plik ZIP do podanego katalogu."""
  with pyzipper.AESZipFile(source_path, 'r') as zf:
    zf.setpassword(password.encode('utf-8'))
    zf.extractall(dest_dir)


def zip_and_remove(password, source_folder: str, folder_docelowy_archiwum : str):
  """
  Sprawdza, czy podany folder nie jest pusty. Jeśli tak, tworzy z jego zawartości
  archiwum ZIP w podkatalogu 'shared' i usuwa oryginalne pliki.

  Args:
      source_folder (str): Ścieżka do folderu, który ma być zarchiwizowany.
  """
  print(f"--- Uruchamiam funkcję archiwizacji dla folderu: '{source_folder}' ---")
  # Sprawdzenie, czy folder źródłowy istnieje
  if not os.path.isdir(source_folder):
    print(f"Błąd: Folder '{source_folder}' nie istnieje.")
    return
  # Sprawdzenie, czy folder jest pusty
  if not os.listdir(source_folder):
    print(f"Informacja: Folder '{source_folder}' jest pusty. Zakończono działanie.")
    return

  try:
    # Generowanie nazwy pliku archiwum na podstawie bieżącej daty i godziny
    teraz = datetime.now()
    arch_name = f"{teraz.strftime('%Y-%m-%d_%H-%M-%S')}.zip"
    zipfile_path = os.path.join(folder_docelowy_archiwum, arch_name)
    print(f"Tworzenie archiwum: {zipfile_path}")
    encrypt_zip(source_folder, zipfile_path, password)
    # Usuwanie oryginalnych plików po pomyślnym utworzeniu archiwum
    print("Usuwanie oryginalnych plików...")
    for fname in os.listdir(source_folder):
      sciezka_pliku = os.path.join(source_folder, fname)
      os.remove(sciezka_pliku)
      print(f"  -> Usunięto: {os.path.basename(sciezka_pliku)}")
    print(f"Sukces! Archiwizacja i czyszczenie folderu '{source_folder}' zakończone.")
  except Exception as e:
    print(f"Wystąpił nieoczekiwany błąd podczas archiwizacji: {e}")


def unzip_and_remove(password, in_folder: str, folder_docelowy: str):
  print(f"\n--- Uruchamiam funkcję rozpakowywania z folderu: '{in_folder}' ---")
  # Sprawdzenie, czy folder z archiwami istnieje
  if not os.path.isdir(in_folder):
    print(f"Błąd: Folder '{in_folder}' nie istnieje.")
    return
  zipfile_exists = False
  for fname in os.listdir(in_folder):
    if fname.endswith('.zip'):
      zipfile_exists = True
      zipfile_path = os.path.join(in_folder, fname)

      # Tworzenie nazwy podkatalogu na podstawie nazwy pliku zip (bez rozszerzenia)
      subdir = os.path.splitext(fname)[0]
      unzip_path = os.path.join(folder_docelowy, subdir)

      print(f"Znaleziono archiwum: {fname}")
      print(f"Rozpakowywanie do: {unzip_path}")
      try:
        decrypt_zip(zipfile_path, unzip_path, password)
        # Usunięcie pliku .zip po pomyślnym rozpakowaniu
        os.remove(zipfile_path)
        print(f"  -> Pomyślnie rozpakowano i usunięto archiwum: {fname}")
      except Exception as e:
        print(f"Wystąpił nieoczekiwany błąd podczas rozpakowywania pliku '{fname}': {e}")
  if not zipfile_exists:
    print(f"Informacja: W folderze '{in_folder}' nie znaleziono żadnych plików .zip.")

def chmod_file(path, user, group, new_permissions = 0o750): 
  try:
      os.chmod(path, new_permissions)
      uid = pwd.getpwnam(user).pw_uid
      gid = grp.getgrnam(group).gr_gid
      os.chown(path, uid, gid)
  except FileNotFoundError:
      print("Błąd: Plik źródłowy nie istnieje.")
  except PermissionError:
      print("Błąd: Brak uprawnień do wykonania operacji. Uruchom skrypt jako root.")
  except Exception as e:
      print(f"Wystąpił nieoczekiwany błąd: {e}")

def copy_file(source_path, destination_path, user, group):
  new_permissions = 0o750
  try:
      shutil.copy2(source_path, destination_path)
      os.chmod(destination_path, new_permissions)
      uid = pwd.getpwnam(user).pw_uid
      gid = grp.getgrnam(group).gr_gid
      os.chown(destination_path, uid, gid)
  except FileNotFoundError:
      print("Błąd: Plik źródłowy nie istnieje.")
  except PermissionError:
      print("Błąd: Brak uprawnień do wykonania operacji. Uruchom skrypt jako root.")
  except Exception as e:
      print(f"Wystąpił nieoczekiwany błąd: {e}")



def test1():
  encrypt_zip('./secure_exchange.py', './dest.zip', 'password')
  decrypt_zip('./dest.zip', './d', 'password')


if __name__ == "__main__":
  myname = os.getenv('MYNAME', '')
  if not myname:
    print('Brak parametru MYNAME')
    exit(0)
  username = os.getenv('USERNAME', 'user1')
  if not username:
    print('Brak parametru USERNAME')
    exit(0)
  action = os.getenv('ACTION', '')
  path_dh_par=f'./{myname}/{username}/dh.par'
  path_priv_key=f'./{myname}/priv/{myname}.key'
  path_my_pub=f'./{myname}/{username}/{myname}.pub'
  path_user_pub=f'./{username}/{myname}/{username}.pub'
  out_folder = f'./{myname}/{username}/out'
  in_folder = f'./{username}/{myname}/out'
  if action=='DH': # generowanie parametrów DH
    generate_dh_par(path_dh_par)
    copy_file(path_dh_par,f'./{username}/{myname}/dh.par',  
              username, 'xsecure')
    chmod_file(path_dh_par, myname, myname, 0o740)
  if action=='KEYS': # generowanie kluczy DH
    generate_dh_keys(path_dh_par, path_priv_key,
                     path_my_pub)
    chmod_file(path_priv_key, myname, myname, 0o700)
    chmod_file(path_my_pub, myname, 'xsecure', 0o740)
  if action=='SEND':
    with open(path_priv_key, 'rb') as f:
      priv_key = load_pem_private_key(f.read(),password=None)
      password = derive_password_from_keys(priv_key, path_user_pub)
      # 1. Przygotowanie środowiska
      folder_to_zip = f'./{myname}/xzip/'
      # 2. Wywołanie archiwizacji
      zip_and_remove(password,folder_to_zip,out_folder)
  if action == 'RECEIVE':
    with open(path_priv_key, 'rb') as f:
      priv_key = load_pem_private_key(f.read(),password=None)
      password = derive_password_from_keys(priv_key, path_user_pub)
      unzip_folder = f'./{myname}/priv'
      unzip_and_remove(password, in_folder, unzip_folder)

