# schemas/account_schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Union
import datetime
from .trans_schemas import TransModel

#from schemas.camel_model import CamelModel


# --- Schematy dla Konta (User) ---
class AccountCreate(BaseModel):
    name: Optional[str] = None
    nip: Optional[str] = Field(None, alias='NIP')
    email: Optional[str] = None
    phone: Optional[str] = None
    password: str  # Dodane pole na hasło, którego brakowało w OpenAPI


class ReturnAccount(BaseModel):
    code: int = Field(description="kod wykonania")
    balance: float = Field(description="saldo")
    balance_cvt: float = Field(description="saldo zamienialne na PLN")
    transactions: List[TransModel]
    description: Optional[str] = Field(default="", description="Opis")
