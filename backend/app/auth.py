"""API-key ingest auth, scrypt password hashing, JWT dashboard login with analyst/admin roles."""
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import User

log = logging.getLogger("uvicorn.error")
_bearer = HTTPBearer(auto_error=False)
_fails: dict[str, list[float]] = {}  # in-memory login throttle (per process)
MAX_FAILS, LOCK_SECONDS = 5, 60


@dataclass
class Principal:
    username: str
    role: str


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    try:
        _, salt, digest = (stored or "scrypt$00$00").split("$")
        probe = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(probe.hex(), digest) and stored is not None
    except ValueError:
        return False


def ensure_secrets() -> None:
    if not settings.jwt_secret:
        settings.jwt_secret = secrets.token_urlsafe(48)
        log.warning("JWT_SECRET not set: generated an ephemeral one (logins reset on restart).")
    if not settings.ingest_api_key:
        settings.ingest_api_key = secrets.token_urlsafe(24)
        log.warning("INGEST_API_KEY not set: generated key for this run: %s", settings.ingest_api_key)


async def seed_users(session: AsyncSession) -> None:
    """Create the admin (and optional analyst) once; existing users are never overwritten."""
    wanted = [(settings.admin_username, settings.admin_password, "admin", True),
              (settings.analyst_username, settings.analyst_password, "analyst", False)]
    for username, password, role, required in wanted:
        if await session.scalar(select(User.id).where(User.username == username)):
            continue
        if not password and not required:
            continue
        generated = not password
        password = password or secrets.token_urlsafe(12)
        session.add(User(username=username, password_hash=hash_password(password), role=role))
        if generated:
            log.warning("Created %s user '%s' with generated password: %s", role, username, password)
    await session.commit()


def make_token(username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode({"sub": username, "role": role, "exp": exp}, settings.jwt_secret, algorithm="HS256")


def check_throttle(key: str) -> None:
    now = time.monotonic()
    recent = [t for t in _fails.get(key, []) if now - t < LOCK_SECONDS]
    _fails[key] = recent
    if len(recent) >= MAX_FAILS:
        raise HTTPException(status_code=429, detail="Too many failed logins; try again in a minute")


def record_failure(key: str) -> None:
    _fails.setdefault(key, []).append(time.monotonic())


async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(creds.credentials, settings.jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}) from exc
    return Principal(username=claims["sub"], role=claims.get("role", "analyst"))


async def require_admin(user: Principal = Depends(current_user)) -> Principal:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


async def require_api_key(request: Request) -> None:
    supplied = request.headers.get("x-api-key", "")
    if not supplied or not hmac.compare_digest(supplied, settings.ingest_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid API key", headers={"WWW-Authenticate": "ApiKey"})
