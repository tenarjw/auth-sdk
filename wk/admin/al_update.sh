# Dodaj nową klasę modelu w models/ (np. models/user_schemas.py).
#Pamiętaj, by ją zaimportować w db/base.py lub models/__init__.py, aby Base ją "zobaczyło".
#Uruchom ponownie alembic revision --autogenerate -m "Add user table".
#Uruchom alembic upgrade head.

# $1 = opis reqizji

alembic revision --autogenerate -m "$1"
alembic upgrade head