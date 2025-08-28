# Używamy lekkiego obrazu Python
FROM python:3.12-slim

# Instalujemy potrzebne biblioteki kryptograficzne
RUN pip install --no-cache-dir cryptography pyzipper

# Kopiujemy skrypt do kontenera
COPY secure_exchange.py /app/secure_exchange.py

# Ustawiamy katalog roboczy
WORKDIR /app

# Definiujemy domyślną komendę startową
ENTRYPOINT ["python", "secure_exchange.py"]
