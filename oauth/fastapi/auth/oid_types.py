# oid_types.py
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, validator
import time


class Introspection(BaseModel):
    active: Optional[bool] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    scope: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    iss: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None


class Token(BaseModel):
    access_token: str = Field(description="Token dostępu wydany przez serwer autoryzacji")
    token_type: str
    expires_in: int = Field(description="Czas życia w sekundach token dostępu")
    refresh_token: str = Field(description="Token odświeżania wystawiony klientowi")
    scope: str = Field(description="Zakres przyznanych tokenów")
    expires_at: int = Field(description="Czas (RFC3339) w którym ważność tokenu wygasa")
    id_token: str = Field(description="Wartość Token ID powiązana z uwierzytelnioną sesją.")

    @validator("expires_in", always=True)
    def calculate_expires_in(cls, v, values):
        if "expires_at" in values:
            return values["expires_at"] - int(time.time())
        return v


class GrantType(Enum):
    authorization_code = 'authorization_code'
    client_credentials = 'client_credentials'


class ResponseType(Enum):
    token = 'token'
    code = 'code'
    id_token_token = 'id_token token'
    id_token = 'id_token'

