# crud/crud_et.py
from sqlalchemy.orm import Session
from models.user import User
from schemas.account_schemas import AccountCreate
import uuid
import random
from schemas.token_schemas import Token
from schemas.wk_schemas import WKUser


# --- Funkcje CRUD dla Użytkownika/Konta ---

def get_or_create_user_from_token(db: Session, token_data: Token) -> User:
    """
    Wyszukuje użytkownika po adresie email z tokenu.
    Jeśli użytkownik nie istnieje, tworzy nowego na podstawie danych z tokenu.
    Zawsze zwraca obiekt użytkownika.
    """
    REFRESH_TOKEN_DATA=False
    # Krok 1: Spróbuj znaleźć istniejącego użytkownika
    try:
      user = get_user_by_email(db, email=token_data.email)
    except:
      user=None

    if user:
        # Opcjonalnie: Zaktualizuj dane użytkownika (np. imię), jeśli zmieniły się w Keycloak
        if REFRESH_TOKEN_DATA and user.name != token_data.username:
            user.name = token_data.username
            db.commit()
            db.refresh(user)
        return user

    # Krok 2: Jeśli użytkownik nie istnieje, utwórz nowego
    try:
        new_user = User(
            email=token_data.email,
            name=token_data.username,
            # Use a placeholder for hashed_password to satisfy NOT NULL constraint
            hashed_password="SSO_USER_NO_PASSWORD",
            # Map additional fields from token_data if available
            # e.g., nip, phone, is_active
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()  # Rollback the session to clear any invalid state
        # Log the error for debugging
        print(f"Error creating user: {str(e)}")
        raise  # Re-raise the exception to handle it upstream or return an error response


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email).first()

def get_user_email(db: Session, id: int) -> str:
    user=db.query(User).filter(User.id == id).first()
    if user:
        return user.email
    else:
        return ''

def create_user(db: Session, user: AccountCreate) -> User:
    # Tutaj powinna być logika haszowania hasła!
    hashed_password = f"hashed_{user.password}" # ZASTĄP PRAWDZIWYM HASZOWANIEM
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        name=user.name,
        nip=user.nip,
        phone=user.phone,
        pesel = user.pesel
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_or_create_user_from_wk_data(db : Session, wk_user: WKUser) -> User:
    user=db.query(User).filter(User.pesel == wk_user.pesel).first()
    if user:
        return user
    return create_user(db,
                       AccountCreate(
                            name=wk_user.first_name+' '+wk_user.last_name,
                            NIP='',
                            email='',
                            phone='',
                            pesel=wk_user.pesel,
                            password=''    )
                       )

