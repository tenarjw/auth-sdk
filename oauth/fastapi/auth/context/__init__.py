from passlib.context import CryptContext
from .database import  DataManager
from .jwk_keys import JwkContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#db_context=DataManager()
jwk_context = JwkContext()




