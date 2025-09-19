# core/config.py

import configparser
import os
from pydantic import BaseModel
from pydantic_settings import BaseSettings

config = configparser.ConfigParser()
ini_path = os.path.join(os.path.dirname(__file__), 'config.ini')
config.read(ini_path)

class LoggingSettings(BaseModel):
  """Model dla sekcji [logging]"""
  level: str
  file: str

class EdrSettings(BaseModel):
  """Model dla sekcji [edr]"""
  address: str
  key: str
  cert: str
  system : str
  url: str


# --- Główna klasa ustawień, która agreguje wszystkie sekcje ---
class Settings(BaseSettings):
  logging: LoggingSettings
  edr: EdrSettings

# --- Logika ładowania ustawień ---
settings = Settings(
  logging=LoggingSettings(**config['logging']),
  edr = EdrSettings(**config['edr']),
)