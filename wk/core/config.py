# core/config.py

import configparser
import os
from pydantic import BaseModel
from pydantic_settings import BaseSettings

# --- Helper do wczytywania i parsowania pliku .ini ---
# Tworzymy parser i wczytujemy plik. Ścieżka jest budowana
# względem lokalizacji tego pliku konfiguracyjnego.
config = configparser.ConfigParser()
ini_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.ini')
config.read(ini_path)

class AppSettings(BaseModel):
  """Model dla sekcji [app]"""
  frontend_url: str

class DBSettings(BaseModel):
  """Model dla sekcji [db]"""
  name: str


class LoggingSettings(BaseModel):
  """Model dla sekcji [logging]"""
  level: str
  file: str

# --- Ustawienia SAML (WK) ---
class WkSettings(BaseModel):
  issuer: str
  provider: str
  enc_key: str
  enc_cert: str
  sign_key:str
  sign_cert:str
  enc_p12 : str
  sign_p12 : str
  password : str
  artifact_resolve_url: str
  logout_url: str
  timeout: int
  sso_url: str
  assertion_consumer_url: str
  saml_post_url : str
  templates:str
  frontend_url : str


# --- Główna klasa ustawień, która agreguje wszystkie sekcje ---

class Settings(BaseSettings):
  # Pydantic automatycznie zrozumie, że ma szukać obiektu 'db' , 'wk' etc...
  app: AppSettings
  db: DBSettings
  logging: LoggingSettings
  wk: WkSettings


settings = Settings(
  app=AppSettings(**config['app']),
  db=DBSettings(**config['db']),
  logging=LoggingSettings(**config['logging']),
  wk = WkSettings(**config['WK']),
)