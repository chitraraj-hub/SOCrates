# backend/src/socrates/api/auth.py
#
# Basic JWT authentication.
# NOTE: Prototype — single hardcoded demo user.
# Production would use PostgreSQL users table with bcrypt passwords.

from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional

from socrates.config import settings

router       = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Hardcoded demo user
DEMO_USER = {
    "username": "analyst",
    "password": "socrates123",
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type:   str
    username:     str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    return jwt.encode(
        {"sub": username, "exp": expire},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def verify_token(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload  = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if (
        form_data.username != DEMO_USER["username"] or
        form_data.password != DEMO_USER["password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    token = create_access_token(form_data.username)
    return Token(
        access_token=token,
        token_type="bearer",
        username=form_data.username,
    )