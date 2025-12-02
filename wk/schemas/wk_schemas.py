# wk_schemas.py
from pydantic import BaseModel

class WKSession(BaseModel):
    relay_state: str
    authn_request_id:  str

class WKUser(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: str
    pesel: str