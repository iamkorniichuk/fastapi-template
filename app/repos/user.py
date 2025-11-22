from uuid import UUID
from sqlmodel import select

from app.core.dependencies import DbDep
from app.models.user import User


def select_user_by_id(db: DbDep, id: UUID) -> User | None:
    query = select(User).where(User.id == id)
    return db.exec(query).first()


def select_user_by_username(db: DbDep, username: str) -> User | None:
    query = select(User).where(User.username == username)
    return db.exec(query).first()


def write_user(db: DbDep, username: str, hashed_password: str) -> User:
    user = User(username=username, hashed_password=hashed_password)

    db.add(user)
    db.commit()
    db.refresh(user)

    return user
