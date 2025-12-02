#!/usr/bin/env python3
# coding: utf-8
# authors: Jerzy Wawro
# (C) JW 2024

import os,sys
import inspect
import time

from requests import Request
from starlette.responses import JSONResponse

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, currentdir)

from fastapi.middleware.cors import CORSMiddleware

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from core.log import log_init

from api.router import v2router

import platform
iis=( platform.uname().system=='Windows' )
if iis:
  # pip install a2wsgi
  # pip install wfastcgi
  # wfastcgi-enable - jako admin po aktywacji venv: https://mtuseeq.medium.com/how-to-deploy-flask-app-on-windows-server-using-fastcgi-and-iis-73d8139d5342
  #D:\er\venv\Scripts\python.exe|D:\etr\venv\Lib\site-packages\wfastcgi.py
  from a2wsgi import ASGIMiddleware
ssl=iis
if ssl:
  import ssl

# logger
import logging
logger = logging.getLogger(__name__)
log_init()

app = FastAPI(debug=True,
              title="WK-Demo",
              description="",
              summary=".",
              version="0.0.1",
              terms_of_service="https://e-talar.pl/terms/",
              contact={
                  "name": "Jerzy Wawro",
                  "url": "https://e-talar/contact/",
                  "email": "info@e-talar.pl",
              },
              license_info={
                  "name": "Apache 2.0",
                  "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
              },
              )

@app.get('/health')
def health():
  return HTMLResponse(f"OK", status_code=200)

# Lista dozwolonych źródeł (domen)
# W środowisku deweloperskim możesz użyć "*" dla wszystkich źródeł,
# ale w produkcji ZAWSZE ograniczaj do konkretnych domen.
origins = [
    "http://localhost:3000",  # Adres Twojej aplikacji Next.js
    "http://127.0.0.1:3000", # Czasem potrzebne, jeśli przeglądarka używa 127.0.0.1 zamiast localhost
  # "https://twoja-domena-produkcyjna.com", # Dodaj domenę produkcyjną, gdy aplikacja będzie wdrożona
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Lista dozwolonych źródeł
    allow_credentials=True, # Zezwól na ciasteczka/nagłówki autoryzacyjne w żądaniach cross-origin
    allow_methods=["*"],    # Zezwól na wszystkie metody HTTP (GET, POST, PUT, DELETE, OPTIONS itp.)
    allow_headers=["*"],    # Zezwól na wszystkie nagłówki w żądaniach cross-origin
)

# Middleware do logowania wywołań
@app.middleware("http")
async def log_requests(request: Request, call_next):
  """
  Middleware do logowania czasu trwania żądania oraz jego statusu.
  """
  start_time = time.time()
  try:
    response = await call_next(request)
  except Exception as e:
    logger.error(f"Request failed: {request.method} {request.url} - Exception: {e}")
    return JSONResponse(status_code=500, content={"message": "Internal Server Error"})

  process_time = time.time() - start_time
  logger.info(f"Request: {request.method} {request.url} - Status: {response.status_code} - Czas: {process_time:.4f}s")
  return response

#app.add_middleware(CORSMiddleware,)

app.mount("/v2", v2router)

origins = ["*"]
origins1 = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


if iis:
  wsgi_app = ASGIMiddleware(app)

@app.get('/', response_model=None)
def get_root():
  return {"message": "WK-Demo w. 001"}

if __name__ == "__main__":
  import uvicorn
  logger.info('Start aplikacji WK Demo')
  from core.config import settings
  logger.info(settings)
  if ssl:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    # openssl pkcs12 -export -out self.pfx -inkey  key.pem -in cert.pem
    # dodaj pfx do zaufanych
    ssl_context.load_cert_chain('./cert.pem', keyfile='./key.pem')
    uvicorn.run(app, host="0.0.0.0", port=8086, \
                ssl_keyfile='./key.pem',
                ssl_certfile='./cert.pem')
    #ssl=ssl_context
    # )
  else:
    uvicorn.run(app, host="0.0.0.0", port=8086)