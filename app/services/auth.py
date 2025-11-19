from datetime import datetime
from uuid import UUID, uuid4
from fastapi import HTTPException
import jwt
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlmodel import select

from app.core.dependencies import DbDep
from app.core.settings import get_settings
from app.models.auth import RefreshToken
from app.models.user import User, UserCreate


hasher = PasswordHash.recommended()
access_token_ttl = get_settings().security.access_token_ttl
refresh_token_ttl = get_settings().security.refresh_token_ttl
algorithm = get_settings().security.encode_algorithm
secret_key = get_settings().security.secret_key


def create_user(db: DbDep, username: str, password: str) -> User:
    query = select(User).where(User.username == username)
    user_exists = db.exec(query).first() is not None
    if user_exists:
        raise HTTPException(
            status_code=400, detail="User with this username already exists"
        )

    try:
        data = UserCreate(username=username, password=password)
    except ValidationError as error:
        raise HTTPException(status_code=400, detail=error.errors())

    hashed_password = hasher.hash(data.password)
    user = User(username=data.username, hashed_password=hashed_password)

    db.add(user)
    db.commit()
    return user


def validate_credentials(db: DbDep, username: str, password: str) -> User:
    query = select(User).where(User.username == username)
    user = db.exec(query).first()
    user_exists = user is not None
    if not user_exists:
        raise HTTPException(
            status_code=400, detail="User with this username doesn't exist"
        )

    password_valid = hasher.verify(password, user.hashed_password)
    if not password_valid:
        raise HTTPException(status_code=400, detail="Incorrect password")

    return user


def validate_refresh_token(db: DbDep, refresh_token: str) -> RefreshToken:
    try:
        payload: dict = jwt.decode(refresh_token, secret_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Refresh token has expired")
    except jwt.InvalidAlgorithmError:
        raise HTTPException(status_code=400, detail="Invalid refresh token algorithm")
    except jwt.ImmatureSignatureError:
        raise HTTPException(status_code=400, detail="Refresh token is not yet valid")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    token_id_hex = payload.get("jti")
    payload_sufficient = token_id_hex is not None
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

    token_valid = hasher.verify(refresh_token, token.hashed_token)
    if not token_valid:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    if token.is_revoked:
        raise HTTPException(status_code=400, detail="Refresh token has been revoked")

    now = datetime.now()
    is_token_expired = token.expires_at < now
    if is_token_expired:
        raise HTTPException(status_code=400, detail="Refresh token has expired")

    return token


def create_access_token(user_id: UUID) -> str:
    issued_at = datetime.now()
    expires_at = issued_at + access_token_ttl
    payload = {
        "sub": user_id.hex,
        "iat": issued_at.timestamp(),
        "exp": expires_at.timestamp(),
        "typ": "access",
    }

    return jwt.encode(payload, secret_key, algorithm=algorithm)


def create_refresh_token(db: DbDep, user_id: UUID) -> str:
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

    token = jwt.encode(payload, secret_key, algorithm=algorithm)
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


def revoke_refresh_token(db: DbDep, refresh_token: RefreshToken):
    refresh_token.is_revoked = True

    db.add(refresh_token)
    db.commit()


def revoke_all_refresh_tokens(db: DbDep, user: User):
    query = select(RefreshToken).where(RefreshToken.user_id == user.id)

    tokens = db.exec(query).all()
    for obj in tokens:
        obj.is_revoked = True
        db.add(obj)
    db.commit()
