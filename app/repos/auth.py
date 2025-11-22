from datetime import datetime
from typing import Sequence
from uuid import UUID
from sqlmodel import select

from app.core.dependencies import DbDep
from app.models.auth import RefreshToken


def select_refresh_token_by_id(db: DbDep, id: UUID) -> RefreshToken | None:
    query = select(RefreshToken).where(RefreshToken.id == id)
    return db.exec(query).first()


def select_all_refresh_tokens_by_user_id(
    db: DbDep, user_id: UUID
) -> Sequence[RefreshToken]:
    query = select(RefreshToken).where(RefreshToken.user_id == user_id)
    return db.exec(query).all()


def write_refresh_token(
    db: DbDep,
    id: UUID,
    user_id: UUID,
    hashed_token: str,
    expires_at: datetime,
) -> RefreshToken:
    token = RefreshToken(
        id=id,
        user_id=user_id,
        hashed_token=hashed_token,
        expires_at=expires_at,
    )

    db.add(token)
    db.commit()
    db.refresh(token)

    return token
