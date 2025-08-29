# db.py
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import DeclarativeBase

# from conf import SQLALCHEMY_DATABASE_URL # Assuming this is correctly configured

# Przykładowa konfiguracja, dostosuj do swoich potrzeb
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Base class for your models
class Base(DeclarativeBase):
    pass

# Create asynchronous engine
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True,
    connect_args={"check_same_thread": False}  # Potrzebne dla SQLite
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    expire_on_commit=False, 
    class_=AsyncSession
)

async def get_db() -> AsyncSession:
    """Zależność do wstrzykiwania sesji do endpointów."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
