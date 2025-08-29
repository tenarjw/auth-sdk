import os,sys

from starlette.authentication import AuthenticationBackend
from starlette.middleware.authentication import AuthenticationMiddleware

from auth.oid_types import ResponseMessage

sys.path.append(os.path.dirname(sys.argv[0]))
import logging
import platform

from fastapi import FastAPI, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from auth.oid_fastapi import router
from auth.context.database import DataManager
from auth.context.session_fastapi import ses_login
from starlette.middleware.sessions import SessionMiddleware

# dla zarządzania bazą
from fastapi import Query
from pydantic import BaseModel
from dependencies.db import get_db, Base, engine

app = FastAPI(
    debug=True,
    title="Test",
    description="OAuth 2.0 and OpenID Connect implementation",
    summary="",
    version="0.0.1",
    terms_of_service="https://example.com/terms/",
    contact={
        "name": "Jerzy Wawro",
        "url": "https://example.com/contact/",
        "email": "jurek@tenar.pl",
    },
    license_info={
      "name": "BSD 3-Clause License",
      "url": "https://opensource.org/licenses/BSD-3-Clause"
    },
    docs_url="/api-docs",
    redoc_url="/api-redoc"
)
# Add SessionMiddleware
# secret key:
# import secrets
# print(secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key="5f0224a510e31c6f56545ab30a93e6a86f0e66b1df6135d37ebcffc251e73611")

app.include_router(router, prefix="/oauth")

# Konfiguracja szablonów
templates = Jinja2Templates(directory="templates")


# Endpoint główny
@app.get("/")
async def root():
    return {"message": "Welcome to the OAuth API. Swagger UI: /api-docs  ReDoc: /api-redoc Login (demo/demo): /login"}


iis=( platform.uname().system=='Windows' )
if iis:
  from a2wsgi import ASGIMiddleware
ssl=iis
if ssl:
  import ssl

logger = logging.getLogger("oapi")
logger.setLevel(logging.DEBUG)

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

#if iis:
#  wsgi_app = ASGIMiddleware(app)
################
# Zdarzenie startowe


@app.on_event("startup")
async def startup_event():
    # tworzy tabele
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created successfully!")


############################# do celów testowych - od razu interface zarządzania bazą
# Modele Pydantic do walidacji danych
class UserCreate(BaseModel):
    ident: str
    secret: str
    email: str = ""
    name: str = ""

class ClientCreate(BaseModel):
    ident: str
    secret: str
    uri: str
    user_id: int = 1


@app.post("/db/demo")
async def insert_demo_data(db: AsyncSession = Depends(get_db)):
    dm = DataManager(db)
    address_id = await dm.add_address(country='Poland')
    # Zwróć uwagę, że tutaj nie ma już await dm.create(db).
    # Tworzenie tabel odbywa się raz, na starcie aplikacji.
    await dm.add_user('demo', 'demo', name='John Down', email='jd@example.com')
    await dm.add_client(ident='demoapp', secret='secret', system_user_id=1, auth_redirect_uri='http://127.0.0.1:3000')
    return {"message": "Demo data inserted successfully"}

@app.get("/db/test")
async def test_data(db: AsyncSession = Depends(get_db)):
    dm = DataManager(db)
    user_id = await dm.check_user('demo', 'demo')
    client = await dm.get_client(1)
    return {
        "user_id": user_id,
        "client": str(client) if client else None
    }

@app.get("/db/uuid")
async def get_client_uuid(id: int = Query(..., description="Client ID"), db: AsyncSession = Depends(get_db)):
    dm = DataManager(db)
    client = await dm.get_client(id)
    if client:
        return {"uuid": client.uuid}
    raise HTTPException(status_code=404, detail="Client not found")

@app.post("/db/user")
async def add_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if not user.ident or not user.secret:
        raise HTTPException(status_code=400, detail="Mandatory parameters: ident, secret")
    dm = DataManager(db)
    user_id = await dm.add_user(user.ident, user.secret, name=user.name, email=user.email)
    return {"message": f"User {user.ident} added with ID {user_id}"}

@app.post("/db/client")
async def add_client(client: ClientCreate, db: AsyncSession = Depends(get_db)):
    if not client.ident or not client.secret or not client.uri:
        raise HTTPException(status_code=400, detail="Mandatory parameters: ident, secret, uri")
    dm = DataManager(db)
    client_id = await dm.add_client(client.ident, client.secret, client.user_id, client.uri)
    return {"message": f"Client {client.ident} added with ID {client_id}"}

###################

##@# Login
# Endpointy formularza logowania
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    dm = DataManager(db)
    user_id = await dm.check_user(username, password)
    if user_id:
        ses_login(user_id, request)
        return templates.TemplateResponse("success.html", {"request": request, "message": "Zalogowano pomyślnie!"})
    else:
        raise HTTPException(status_code=401, detail="Nieprawidłowy login lub hasło")

@app.post("/login_json", response_model=ResponseMessage)
async def login_json(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
) -> ResponseMessage:
    dm = DataManager(db)
    user_id = await dm.check_user(username, password)
    if user_id:
        ses_login(user_id, request)
        return ResponseMessage(message="Zalogowano pomyślnie!")
    else:
        return ResponseMessage(code=-1, message="Nieprawidłowy login lub hasło")

if __name__ == "__main__":
  import uvicorn
  if ssl:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    # openssl pkcs12 -export -out self.pfx -inkey  key.pem -in cert.pem
    # dodaj pfx do zaufanych
    ssl_context.load_cert_chain('./cert.pem', keyfile='./key.pem')
    uvicorn.run(app, host="0.0.0.0", port=8088,
                ssl_keyfile='./key.pem',
                ssl_certfile='./cert.pem')
    #ssl=ssl_context
    # )
  else:
    uvicorn.run(app, host="0.0.0.0", port=8088)