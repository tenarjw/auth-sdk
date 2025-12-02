# db/session.py
from sqlalchemy import create_engine
import sqlalchemy, sqlite3
from sqlalchemy.orm import sessionmaker
from core.config import settings

import os

def connection_string(name):
  app_dir = os.getcwd()
  os.makedirs(app_dir, exist_ok=True)   # tworzy folder jeśli go nie ma
  db_path = os.path.join(app_dir, name)
  return f"sqlite:///{db_path}"

# Tworzymy silnik bazy danych - JEDEN RAZ na całe życie aplikacji
engine = create_engine(connection_string(settings.db.name), connect_args={})

# Tworzymy fabrykę sesji - JEDEN RAZ na całe życie aplikacji
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)