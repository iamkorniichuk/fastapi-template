from datetime import datetime
from typing import Literal, TypedDict
from uuid import UUID, uuid4
from fastapi import HTTPException
import jwt
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlmodel import select

from app.core.dependencies import AuthCredentialsDep, DbDep
from app.core.settings import get_settings
from app.models.auth import RefreshToken
from app.models.user import User, UserCreate


hasher = PasswordHash.recommended()
access_token_ttl = get_settings().security.access_token_ttl
refresh_token_ttl = get_settings().security.refresh_token_ttl
algorithm = get_settings().security.encode_algorithm
secret_key = get_settings().security.secret_key


TokenType = Literal["access"] | Literal["refresh"]


class TokenPayload(TypedDict):
    jti: str
    sub: str
    iat: float
    exp: float
    typ: TokenType


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
            status_code=401, detail="User with this username doesn't exist"
        )

    password_valid = hasher.verify(password, user.hashed_password)
    if not password_valid:
        raise HTTPException(status_code=400, detail="Incorrect password")

    return user


def decode_token(token: str, expected_type: TokenType) -> TokenPayload:
    try:
        payload: dict = jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token has expired")
    except jwt.InvalidAlgorithmError:
        raise HTTPException(status_code=400, detail="Invalid token algorithm")
    except jwt.ImmatureSignatureError:
        raise HTTPException(status_code=400, detail="Token is not yet valid")
    except jwt.DecodeError:
        raise HTTPException(status_code=400, detail="Invalid token")

    payload_sufficient = (
        payload.get("jti") is not None
        and payload.get("sub") is not None
        and payload.get("iat") is not None
        and payload.get("exp") is not None
        and payload.get("typ") is not None
    )
    if not payload_sufficient:
        raise HTTPException(
            status_code=400, detail="Token payload is missing required fields"
        )

    type_correct = payload["typ"] == expected_type
    if not type_correct:
        raise HTTPException(status_code=400, detail="Token type is not correct")

    return TokenPayload(**payload)


def validate_refresh_token(db: DbDep, refresh_token: str) -> RefreshToken:
    payload = decode_token(refresh_token, "refresh")

    token_id = UUID(payload["jti"])
    query = select(RefreshToken).where(RefreshToken.id == token_id)
    token = db.exec(query).first()
    token_exists = token is not None
    if not token_exists:
        raise HTTPException(status_code=401, detail="Token not found")

    token_valid = hasher.verify(refresh_token, token.hashed_token)
    if not token_valid:
        raise HTTPException(status_code=400, detail="Invalid token")

    if token.is_revoked:
        raise HTTPException(status_code=400, detail="Token has been revoked")

    now = datetime.now()
    is_token_expired = token.expires_at < now
    if is_token_expired:
        raise HTTPException(status_code=400, detail="Token has expired")

    return token


def create_access_token(user_id: UUID) -> str:
    token_id = uuid4()
    issued_at = datetime.now()
    expires_at = issued_at + access_token_ttl
    payload = {
        "jti": token_id.hex,
        "sub": user_id.hex,
        "iat": issued_at.timestamp(),
        "exp": expires_at.timestamp(),
        "typ": "access",
    }

    return jwt.encode(payload, secret_key, algorithm=algorithm)


def create_refresh_token(db: DbDep, user_id: UUID) -> str:
    token_id = uuid4()
    issued_at = datetime.now()
    expires_at = issued_at + refresh_token_ttl
    payload = {
        "jti": token_id.hex,
        "sub": user_id.hex,
        "iat": issued_at.timestamp(),
        "exp": expires_at.timestamp(),
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


def get_current_user(db: DbDep, credentials: AuthCredentialsDep):
    credentials_provided = credentials is not None
    if not credentials_provided:
        raise HTTPException(status_code=401, detail="Authentication required")

    token = credentials.credentials
    payload = decode_token(token, "access")

    user_id = UUID(payload["sub"])
    query = select(User).where(User.id == user_id)
    user = db.exec(query).first()

    user_exists = user is not None
    if not user_exists:
        raise HTTPException(status_code=401, detail="User not found")

    return user
