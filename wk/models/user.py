# models/user_schemas.py
import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean
from sqlalchemy.orm import relationship

from db.base import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    wk_ident = Column(String(20), nullable=True, index=True)
    name = Column(String(100), nullable=True)
    nip = Column(String(20), nullable=True, index=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    phone = Column(String(20), nullable=True)

    hashed_password = Column(String, nullable=True)  # OpenAPI nie specyfikuje, ale to konieczne
    balance = Column(Float, default=0.0)

    is_active = Column(Boolean, default=True)
    creation_date = Column(DateTime, default=datetime.datetime.now)

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', balance={self.balance})>"