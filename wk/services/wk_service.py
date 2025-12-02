import base64

from sqlalchemy.orm import Session
from typing import List, Optional

from core.config import settings
from crud.crud_user import get_user_by_wk_ident, crud_user
from lib.token import create_token
from models import wk as model_wk
from schemas import wk_schemas
import hashlib

def pesel_to_email(pesel: str, domain: str = "example.com", length: int = 6) -> str:
    # przy logowaniu z WK mamy pesel, nie mamy maila. Tworzymy fikcyjny
    # adres e-mail, którego prefixem jest hash SHA-256 wygenerowany z PESEL-u.

    # upewnienie się, że PESEL jest traktowany jako tekst
    pesel_bytes = pesel.encode("utf-8")
    # BLAKE2s tworzy bardzo krótki hash
    h = hashlib.blake2s(pesel.encode("utf-8"), digest_size=length).digest()
    prefix = base64.b32encode(h).decode("ascii").rstrip("=")
    email = f"{prefix}@{domain}"
    return email

def get_wk(db: Session, sess_id: int) -> Optional[model_wk.WKSessionBase]:
    return db.query(model_wk.WKSessionBase).filter(model_wk.WKSessionBase.id == sess_id).first()

def get_wk_by_state(db: Session, state: str) -> model_wk.WKSessionBase:
    return (db.query(model_wk.WKSessionBase).filter(model_wk.WKSessionBase.relay_state == state).first())

def create_wk(db: Session, wk_session: wk_schemas.WKSession) -> model_wk.WKSessionBase:
    db_wk = model_wk.WKSessionBase(**wk_session.model_dump())
    db.add(db_wk)
    db.commit()
    db.refresh(db_wk)
    return db_wk

def update_wk_session(db: Session, authn_request_id, token : str, name_id : str, session_index: str) -> model_wk.WKSessionBase:
    db_wk=db.query(model_wk.WKSessionBase).filter(model_wk.WKSessionBase.authn_request_id == authn_request_id).first()
    if db_wk:
        db_wk.session_index=session_index
        db_wk.name_id = name_id
        db_wk.token = token
        db.add(db_wk)
        db.commit()
        db.refresh(db_wk)
    return db_wk

def token_for_wk_user(db: Session, wk_ident: str, name: str, name_id : str, session_index: str, authn_request_id=''):
    user = get_user_by_wk_ident(db, wk_ident)
    if user:
        email=user.email
    else:
        email=pesel_to_email(wk_ident)
        user = crud_user.create_user(db, user_data={"wk_ident": wk_ident, 'name': name, 'email':email})
    token = create_token(settings.wk.issuer, user.id, 0, {'email':email})
    update_wk_session(db,authn_request_id,token,name_id,session_index)
    return(token,email)

def token2session(db: Session, token : str):
    session : model_wk.WKSessionBase = db.query(model_wk.WKSessionBase).filter(model_wk.WKSessionBase.token == token).first()
    if session:
        return (session.name_id,session.session_index)
    else:
        return ('','')
