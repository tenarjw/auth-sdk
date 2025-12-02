# models/wk.py
import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from db.base import Base

class WKSessionBase(Base):
    __tablename__ = 'wk'

    id = Column(Integer, primary_key=True, index=True)
    relay_state = Column(String)
    authn_request_id = Column(String)
    generated_at = Column(DateTime, default=datetime.datetime.now)
    token = Column(String)
    name_id = Column(String)
    session_index = Column(String)

