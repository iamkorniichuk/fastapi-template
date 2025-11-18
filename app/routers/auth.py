from datetime import datetime
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException
import jwt
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlmodel import SQLModel, select

from app.core.dependencies import AuthFormDep, DbDep
from app.core.settings import get_settings
from app.models.auth import RefreshToken
from app.models.user import User, UserCreate


router = APIRouter()

hasher = PasswordHash.recommended()
access_token_ttl = get_settings().security.access_token_ttl
refresh_token_ttl = get_settings().security.refresh_token_ttl
algorithm = get_settings().security.encode_algorithm
secret_key = get_settings().security.secret_key


class ReadAuthToken(SQLModel):
    access_token: str
    refresh_token: str


class CreateRefreshToken(SQLModel):
    refresh_token: str


@router.post("/sign-up", status_code=201)
def sign_up(db: DbDep, auth_form: AuthFormDep):
    query = select(User).where(User.username == auth_form.username)
    user_exists = db.exec(query).first() is not None
    if user_exists:
        raise HTTPException(
            status_code=400, detail="User with this username already exists"
        )

    try:
        data = UserCreate(username=auth_form.username, password=auth_form.password)
    except ValidationError as error:
        raise HTTPException(status_code=400, detail=error.errors())

    hashed_password = hasher.hash(data.password)
    user = User(username=data.username, hashed_password=hashed_password)

    db.add(user)
    db.commit()

    refresh_token = _create_refresh_token(user.id, db, commit=True)
    access_token = _create_access_token(user.id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


@router.post("/login")
def login(db: DbDep, auth_form: AuthFormDep):
    query = select(User).where(User.username == auth_form.username)
    user = db.exec(query).first()
    user_exists = user is not None
    if not user_exists:
        raise HTTPException(
            status_code=400, detail="User with this username doesn't exist"
        )

    password_valid = hasher.verify(auth_form.password, user.hashed_password)
    if not password_valid:
        raise HTTPException(status_code=400, detail="Incorrect password")

    refresh_token = _create_refresh_token(user.id, db, commit=True)
    access_token = _create_access_token(user.id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh")
def refresh(db: DbDep, data: CreateRefreshToken):
    try:
        payload: dict = jwt.decode(
            data.refresh_token, secret_key, algorithms=[algorithm]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Refresh token has expired")
    except jwt.InvalidAlgorithmError:
        raise HTTPException(status_code=400, detail="Invalid refresh token algorithm")
    except jwt.ImmatureSignatureError:
        raise HTTPException(status_code=400, detail="Refresh token is not yet valid")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    token_id_hex = payload.get("jti")
    user_id_hex = payload.get("sub")
    payload_sufficient = token_id_hex is not None and user_id_hex is not None
    if not payload_sufficient:
        raise HTTPException(
            status_code=400, detail="Refresh token payload is missing required fields"
        )

    token_id = UUID(token_id_hex)
    query = select(RefreshToken).where(RefreshToken.id == token_id)
    token = db.exec(query).first()
    token_exists = token is not None
    if not token_exists:
        raise HTTPException(status_code=400, detail="Refresh token not found")

    token_valid = hasher.verify(data.refresh_token, token.hashed_token)
    if not token_valid:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    now = datetime.now()
    is_token_expired = token.expires_at < now
    if is_token_expired:
        raise HTTPException(status_code=400, detail="Refresh token has expired")

    user_id = UUID(user_id_hex)
    refresh_token = _create_refresh_token(user_id, db, commit=True)
    access_token = _create_access_token(user_id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


def _create_access_token(user_id: UUID) -> str:
    issued_at = datetime.now()
    expires_at = issued_at + access_token_ttl
    payload = {
        "sub": user_id.hex,
        "iat": issued_at.timestamp(),
        "exp": expires_at.timestamp(),
        "typ": "access",
    }

    return jwt.encode(payload, secret_key, algorithm)


def _create_refresh_token(
    user_id: UUID, db: DbDep | None = None, commit: bool = False
) -> str:
    assert not commit or db is not None

    issued_at = datetime.now()
    expires_at = issued_at + refresh_token_ttl
    token_id = uuid4()
    payload = {
        "sub": user_id.hex,
        "iat": issued_at.timestamp(),
        "exp": expires_at.timestamp(),
        "jti": token_id.hex,
        "typ": "refresh",
    }

    token = jwt.encode(payload, secret_key, algorithm)
    if not commit or db is None:
        return token

    hashed_token = hasher.hash(token)

    obj = RefreshToken(
        id=token_id,
        user_id=user_id,
        hashed_token=hashed_token,
        expires_at=expires_at,
    )
    db.add(obj)
    db.commit()

    return token
