# db/base.py
from sqlalchemy.orm import declarative_base

# Wszystkie modele ORM będą dziedziczyć po tej klasie
Base = declarative_base()