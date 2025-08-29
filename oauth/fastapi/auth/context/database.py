from sqlalchemy import Column, Integer, String, Sequence, select, delete, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from auth.util import verify_password, hash_password
import conf
from dependencies.db import Base # Pamiętaj, że ten import wymaga pliku db.py z odpowiednią bazą

# Modele danych - pozostawione bez zmian
class User(Base):
  __tablename__ = 'user'
  __table_args__ = {'extend_existing': True}
  id = Column(Integer, Sequence('usr_id_seq'), primary_key=True)
  login = Column(String(30))
  password = Column(String(200))
  scopes = Column(String(1024))
  email = Column(String(50))
  phone_number = Column(String(10))
  name = Column(String(30))
  family_name = Column(String(30))
  given_name = Column(String(30))

  def is_active(self):
    return True

  def get_id(self):
    return self.id

  def __repr__(self):
    return '<User %r>' % self.login


class Client(Base):
  __tablename__ = 'client_app'
  id = Column(Integer, Sequence('capp_id_seq'), primary_key=True)
  ident = Column(String(40))
  secret = Column(String(40))
  system_user_id = Column(Integer)
  auth_redirect_uri = Column(String(500))
  uuid = Column(String(40))
  scopes = Column(String(1024))

  def __repr__(self):
    return "<Client('%s', '%s')>" % (self.id, self.auth_redirect_uri)


class Token(Base):
  __tablename__ = 'token'
  id = Column(Integer, Sequence('tkn_id_seq'), primary_key=True)
  token = Column(String(200))
  token_type = Column(String(20))
  client_id = Column(Integer)
  user_id = Column(Integer)
  expires_at = Column(Integer)
  expires_in = Column(Integer)
  refresh_token = Column(String(200))
  scope = Column(String(1024))

  def __repr__(self):
    return "<Token('%s', '%s', '%s)>" % (self.token, self.client_id, self.user_id)


class Session(Base):
  __tablename__ = 'db'
  sid = Column(String(100), primary_key=True)
  client_id = Column(Integer)
  user_id = Column(Integer)

  def __repr__(self):
    return "<Session('%s', '%s', '%s)>" % (self.sid, self.client_id, self.user_id)


class Address(Base):
  __tablename__ = 'address'
  id = Column(Integer, Sequence('addr_id_seq'), primary_key=True)
  country = Column(String(100))


class DataManager:
  db: AsyncSession = None
  
  def __init__(self, db : AsyncSession):
    self.db=db
    

  def create(self): # create database
    try:
      self.engine = create_engine(conf.SQLALCHEMY_DATABASE_URL, echo=True)
      result = Base.metadata.create_all(self.engine)
      print(result)
    except Exception as e:
      print('DB error [%s]' % e)

  async def add_user(self, login, password, name, email):
    # Haszowanie hasła odbywa się w `auth/util.py`
    hashed_password = hash_password(password)
    new_user = User(
      login=login,
      password=hashed_password,
      name=name,
      email=email,
      scopes="demo_scope"
    )
    self.db.add(new_user)
    # Nie robimy tu commit, zaleznosc w fastAPI to zrobi
    await self.db.flush()
    return new_user.id # Zwracamy id dla uzytku w endpointach


  async def check_user(self, login, password):
    try:
      u = await self.db.scalar(select(User).filter_by(login=login))
      if not u:
        return 0
      if verify_password(password, u.password):
        return u.id
      return 0
    except Exception as e:
      print(f'Error checking user: {str(e)}')
      return 0

  async def int_user_id(self, login):
    try:
      user = await self.db.scalar(select(User).filter_by(login=login))
      return user.id if user else 0
    except Exception as e:
      print(f'Error getting user ID: {str(e)}')
      return 0

  async def ext_user_id(self, user_id):
    try:
      user = await self.db.scalar(select(User).filter_by(id=user_id))
      return user.login if user else None
    except Exception as e:
      print(f'Error getting user login: {str(e)}')
      return None

  async def int_client_id(self, uuid):
    if not uuid:
      return 0
    try:
      client = await self.db.scalar(select(Client).filter_by(uuid=uuid))
      return client.id if client else 0
    except Exception as e:
      print(f'Error getting client ID: {str(e)}')
      return 0

  async def user_by_id(self, userid):
    try:
      user=await  self.db.scalar(select(User).filter_by(id=userid))
      return user
    except Exception as e:
      print(f'Error getting user by ID: {str(e)}')
      raise

  async def user_by_name(self, name):
    try:
      user= await self.db.scalar(select(User).filter_by(login=name))
      return user
    except Exception as e:
      print(f'Error getting user by name: {str(e)}')
      return None

  async def add_address(self, country: str):
    new_address = Address(country=country)
    self.db.add(new_address)
    await self.db.flush()  # Wykonanie flush asynchronicznie
    await self.db.commit()  # Zatwierdzenie zmian w bazie danych
    return new_address.id

  async def add_client(self, ident, secret, system_user_id, auth_redirect_uri):
    new_client = Client(
        ident=ident,
        secret=secret,
        system_user_id=system_user_id,
        auth_redirect_uri=auth_redirect_uri
    )
    self.db.add(new_client)
    await self.db.flush()  # Wykonanie flush asynchronicznie
    await self.db.commit()  # Zatwierdzenie zmian w bazie danych

  async def get_client(self, client_id):
    try:
      client=await self.db.scalar(select(Client).filter_by(id=client_id))
      return client
    except Exception as e:
      print(f'Error getting client: {str(e)}')
      return None

  async def get_client_uuid(self, client_id):
    try:
      client=await self.db.scalar(select(Client).filter_by(uuid=client_id))
      return client
    except Exception as e:
      print(f'Error getting client by UUID: {str(e)}')
      return None

  async def delete_access_tokens(self):
    try:
        async with self.db.begin():  # Rozpoczyna transakcję
            result = await self.db.execute(delete(Token))  # Asynchroniczne usunięcie rekordów
            # Opcjonalnie: zwróć liczbę usuniętych rekordów
            return {"deleted_rows": result.rowcount}
    except SQLAlchemyError as e:
        await self.db.rollback()  # Wycofanie zmian w razie błędu
        raise Exception(f"Failed to delete tokens: {str(e)}")

  async def put_access_token(self, token, client_id, user_id=0):
    try:
        async with self.db.begin():  # Rozpoczyna transakcję
            result = self.db.execute(delete(Token).where(Token.client_id == client_id, Token.user_id == user_id))
    except SQLAlchemyError as e:
        await self.db.rollback()  # Wycofanie zmian w razie błędu
    try:
      tk = Token(
        token=token,
        token_type = 'access_token',
        client_id = client_id,
        user_id = user_id,
        #expires_at = ?,
        #expires_in = ?,
        refresh_token = '',
        scope = ''
        )
      self.db.add(tk)
      await self.db.flush()
      await self.db.commit()
      return tk
    except Exception as e:
      print(f'Error managing access token: {str(e)}')
      raise

  async def get_access_token(self, client_id=0, user_id=0):
    try:
      token=await self.db.scalar(select(Token).filter_by(client_id=client_id, user_id=user_id))
      return token
    except Exception as e:
      print(f'Error getting access token: {str(e)}')
      return None

  async def token_owner(self, token):
    try:
      tk = await self.db.scalar(select(Token).filter_by(token=token))
      if tk:
        return (tk.user_id, tk.client_id)
      return (0, 0)
    except Exception as e:
      print(f'Error getting token owner: {str(e)}')
      return (0, 0)

  async def put_session(self, sid, uid):
    try:
      # Lepszy wzorzec, uzyj jednego bloku try/except
      s = Session(sid, user_id=uid)
      self.db.add(s)
      await self.db.flush()
      await self.db.commit()
      return s
    except Exception as e:
      print(f'Error adding db: {str(e)}')
      raise

  async def pop_session(self, sid, uid):
    try:
        async with self.db.begin():
            result = self.db.execute(delete(Session).where(Session.sid == sid, Session.user_id == uid))
            return {"deleted_rows": result.rowcount}
    except SQLAlchemyError as e:
        await self.db.rollback()
        raise Exception(f"Failed to delete session: {str(e)}")


  async def get_session_uid(self, sid):
    try:
      ses=await self.db.scalar(select(Session).filter_by(sid=sid))
      return ses
    except Exception as e:
      print(f'Error getting db UID: {str(e)}')
      return None

  async def check_session(self, sid, uid):
    try:
      s = await self.db.scalar(select(Session).filter_by(sid=sid, user_id=uid))
      return True if s else False
    except Exception as e:
      print(f'Error checking db: {str(e)}')
      return False

  async def token_for_session(self, sid, uid):
    try:
      s = await self.db.scalar(select(Session).filter_by(sid=sid, user_id=uid))
      if s:
        return await self.get_access_token(user_id=uid, db=self.db)
      return None
    except Exception as e:
      print(f'Error getting token for db: {str(e)}')
      return None
