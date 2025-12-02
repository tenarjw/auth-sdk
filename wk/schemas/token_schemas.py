# schemas/token_schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Union
import datetime

from schemas.camel_model import CamelModel


# --- Schematy podstawowe ---
class ReturnBasic(BaseModel):
    code: int = Field(description="kod wykonania")
    result: str = Field(description="komunikat")

class Token(BaseModel):
  username: str
  email : str
  message : str
  scope : str
  roles: List[str]

# --- Schematy dla OTP ---
class ReturnOTP(CamelModel):
    code: int = Field(description="kod wykonania")
    secret_key: str = Field(description="sekretny kod OTP")

