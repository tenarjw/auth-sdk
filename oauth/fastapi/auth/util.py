# auth/util.py
from passlib.context import CryptContext

# Kontekst hashowania. Możesz użyć 'argon2', 'scrypt', 'pbkdf2_sha256'
# Zdecydowanie polecany jest 'bcrypt' lub 'argon2'
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Haszuje hasło."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Weryfikuje hasło, sprawdzając, czy tekstowe hasło odpowiada zahaszowanemu."""
    return pwd_context.verify(plain_password, hashed_password)

