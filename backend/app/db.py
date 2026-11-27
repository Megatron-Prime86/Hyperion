import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

from alembic import command
from alembic.config import Config

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models import Base

_kwargs: dict = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    _kwargs = {"connect_args": {"check_same_thread": False}}

engine = create_async_engine(settings.database_url, **_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def alembic_config() -> Config:
    for base in (Path.cwd(), Path(__file__).resolve().parents[1]):
        if (base / "alembic.ini").exists():
            return Config(str(base / "alembic.ini"))
    raise FileNotFoundError("alembic.ini not found")


async def migrate() -> None:
    """Apply Alembic migrations (run in a thread: env.py drives its own event loop)."""
    await asyncio.to_thread(command.upgrade, alembic_config(), "head")


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
