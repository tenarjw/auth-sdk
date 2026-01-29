# core/config.py

import configparser
import os
from pydantic import BaseModel
from pydantic_settings import BaseSettings

config = configparser.ConfigParser()
ini_path = os.path.join(os.path.dirname(__file__), 'config.ini')
config.read(ini_path)

class KSeF2Settings(BaseModel):
  """Model dla sekcji [ksef2]"""
  cert_pfx: str
  cert_pass: str
  nip : str
  api_url : str

# --- Główna klasa ustawień, która agreguje wszystkie sekcje ---
class Settings(BaseSettings):
  ksef2: KSeF2Settings

# --- Logika ładowania ustawień ---
settings = Settings(
  ksef2 = KSeF2Settings(**config['ksef2']),
)