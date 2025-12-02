# crud/crud_user.py
from typing import Optional

from fastapi.openapi.models import EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select

from crud.base import CRUDBase
from models.user import User
from schemas.user_schemas import UserCreate, UserInDB

class CRUDUser(CRUDBase[User, UserCreate, UserInDB]):
    #async \
    def get_user_by_email(self, db: Session, email: str) -> Optional[User]:
        result = db.execute(select(User).filter(User.email == email))
        return result.scalars().first()

    def get_user_by_id(self, db: Session, id) -> Optional[User]:
        result = db.execute(select(User).filter(User.id == id))
        return result.scalars().first()

    def create_user(self, db: Session, *, user_data: dict) -> User:
        # Assuming user_data contains at least 'email' and 'id_from_keycloak' (optional)
        db_obj = User(**user_data)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

crud_user = CRUDUser(User)


def get_email_by_user_id(db: Session, id) -> EmailStr:
    try:
        result = db.execute(select(User).filter(User.id == id))
        return result.scalars().first().email
    except:
        return ''

def get_user_by_wk_ident(db: Session, wk_ident) -> Optional[User]:
    result = db.execute(select(User).filter(User.wk_ident == wk_ident))
    return result.scalars().first()

def update_otp_secret(db: Session, user : User, otp_secret: str) -> str:
  if user:
    user.otp_secret = otp_secret
    db.add(user)
    db.commit()
  return otp_secret
