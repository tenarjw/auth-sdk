import json_logging
import logging
from core.config import settings


# 1. Klasa filtrująca
class HealthCheckFilter(logging.Filter):
  """
  Filtr pomijający logi, których treść (msg) zawiera '/health'.
  Zakłada, że log Uvicorn/FastAPI dla sondy zawiera tę ścieżkę.
  """
  def filter(self, record):
    # Sprawdzamy, czy log jest typu string i zawiera /health
    if isinstance(record.msg, str) and "/health" in record.msg:
      return False  # Pomijaj ten rekord (nie loguj)
    return True  # Loguj pozostałe rekordy


# 2. Zmodyfikowana funkcja konfiguracji logów
def log_init():
  LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
  formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

  root_logger = logging.getLogger()
  # Zmniejszenie poziomu logowania na root loggerze, jeśli to konieczne,
  # aby uniknąć duplikatów logów z loggerów Uvicorna.
  # W kontekście Uvicorn, często lepsze jest konfiguracja bezpośrednio
  # dla loggerów 'uvicorn.access' i 'uvicorn.error'.
  if settings.logging.level=='DEBUG':
    level=logging.DEBUG
  else:
    level=logging.INFO
  root_logger.setLevel(level)
  LOG_FILE_PATH = settings.logging.file
  file_handler = logging.FileHandler(LOG_FILE_PATH)
  file_handler.setFormatter(formatter)

  # Dodanie filtru do FileHandler
  health_filter = HealthCheckFilter()
  file_handler.addFilter(health_filter)

  # Aplikacja handlera do loggera dostępu Uvicorn
  uvicorn_access_logger = logging.getLogger("uvicorn.access")
  uvicorn_access_logger.addHandler(file_handler)

  # Jeśli nie chcesz logować logów aplikacji (np. print("Moja aplikacja")),
  # wyłącz dodanie handlera do root_logger:
  # root_logger=logging.getLogger()
  root_logger.addHandler(file_handler)


