from datetime import datetime
from uuid import UUID

from app.core.dependencies import DbDep
from app.domains.auth.errors import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from app.domains.auth.rules import (
    create_access_token_payload,
    create_refresh_token_payload,
)
from app.domains.auth.validators import (
    validate_access_token_payload,
    validate_refresh_token_payload,
)
from app.domains.errors import (
    AlreadyExistsError,
    NotFoundError,
    InvalidValueError,
)
from app.domains.user.validators import validate_password_strength
from app.models.auth import RefreshToken
from app.models.user import User
from app.repos.auth import (
    write_refresh_token,
    select_all_refresh_tokens_by_user_id,
    select_refresh_token_by_id,
)
from app.repos.user import select_user_by_id, select_user_by_username, write_user
from app.utils import hasher, jwt


def signup_user(db: DbDep, username: str, password: str) -> User:
    user = select_user_by_username(db, username)
    if user is not None:
        raise AlreadyExistsError("User with this username already exists")

    validate_password_strength(password)
    hashed_password = hasher.hash(password)
    return write_user(db, username, hashed_password)


def login_user(db: DbDep, username: str, password: str) -> User:
    user = select_user_by_username(db, username)
    if user is None:
        raise NotFoundError("User not found")

    password_valid = hasher.verify(password, user.hashed_password)
    if not password_valid:
        raise InvalidValueError("Password doesn't match user's credentials")

    return user


def validate_refresh_token(db: DbDep, refresh_token: str) -> RefreshToken:
    payload = jwt.decode(refresh_token)
    validate_refresh_token_payload(payload)

    token = select_refresh_token_by_id(db, payload["jti"])
    token_exists = token is not None
    if not token_exists:
        raise NotFoundError("Token not found")

    token_valid = hasher.verify(refresh_token, token.hashed_token)
    if not token_valid:
        raise TokenInvalidError("Invalid token")

    if token.is_revoked:
        raise TokenRevokedError("Token has been revoked")

    now = datetime.now()
    is_token_expired = token.expires_at < now
    if is_token_expired:
        raise TokenExpiredError("Token has expired")

    return token


def generate_tokens(db: DbDep, user_id: UUID):
    access_token_payload = create_access_token_payload(user_id)
    refresh_token_payload = create_refresh_token_payload(user_id)

    access_token = jwt.encode(access_token_payload)  # type: ignore
    refresh_token = jwt.encode(refresh_token_payload)  # type: ignore

    hashed_refresh_token = hasher.hash(refresh_token)
    id = UUID(hex=refresh_token_payload["jti"])
    user_id = UUID(hex=refresh_token_payload["sub"])
    expires_at = datetime.fromtimestamp(refresh_token_payload["exp"])
    write_refresh_token(
        db,
        id=id,
        user_id=user_id,
        hashed_token=hashed_refresh_token,
        expires_at=expires_at,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


def revoke_refresh_token(db: DbDep, refresh_token: RefreshToken):
    refresh_token.is_revoked = True

    db.add(refresh_token)
    db.commit()


def revoke_all_refresh_tokens(db: DbDep, user: User):
    tokens = select_all_refresh_tokens_by_user_id(db, user.id)
    for obj in tokens:
        obj.is_revoked = True
        db.add(obj)
    db.commit()


def get_current_user(db: DbDep, access_token: str) -> User:
    payload = jwt.decode(access_token)
    validate_access_token_payload(payload)

    id = UUID(hex=payload["sub"])
    user = select_user_by_id(db, id)

    if user is None:
        raise NotFoundError("User not found")

    return user
