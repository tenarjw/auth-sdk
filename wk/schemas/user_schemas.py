# schemas/user_schemas.py
from pydantic import BaseModel, EmailStr, ConfigDict
from schemas.camel_model import CamelModel

class UserBase(CamelModel):
    email: EmailStr

class UserCreate(UserBase):
    pass # No password directly here if Keycloak handles it

class UserInDB(UserBase):
    id: int
    id_from_keycloak: str | None = None

#    class Config:
#        orm_mode = True # Enable ORM mode for Pydantic to read from SQLAlchemy models
    # Zmieniono 'Config' na 'model_config' i 'orm_mode' na 'from_attributes'
    # model_config = ConfigDict(from_attributes=True) # jest to w CamelModel