from fastapi import APIRouter
from sqlmodel import SQLModel

from app.core.dependencies import AuthFormDep, DbDep
from app.services.auth import (
    create_user,
    create_refresh_token,
    create_access_token,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    validate_credentials,
    validate_refresh_token,
)

router = APIRouter()


class ReadAuthToken(SQLModel):
    access_token: str
    refresh_token: str


class CreateRefreshToken(SQLModel):
    refresh_token: str


@router.post("/sign-up", status_code=201)
def sign_up(db: DbDep, auth_form: AuthFormDep):
    user = create_user(db, auth_form.username, auth_form.password)
    refresh_token = create_refresh_token(db, user.id)
    access_token = create_access_token(user.id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


@router.post("/login")
def login(db: DbDep, auth_form: AuthFormDep):
    user = validate_credentials(db, auth_form.username, auth_form.password)
    refresh_token = create_refresh_token(db, user.id)
    access_token = create_access_token(user.id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh")
def refresh(db: DbDep, data: CreateRefreshToken):
    token = validate_refresh_token(db, data.refresh_token)

    user_id = token.user_id
    refresh_token = create_refresh_token(db, user_id)
    access_token = create_access_token(user_id)
    return ReadAuthToken(access_token=access_token, refresh_token=refresh_token)


@router.post("/logout", status_code=204)
def logout(db: DbDep, data: CreateRefreshToken):
    token = validate_refresh_token(db, data.refresh_token)
    revoke_refresh_token(db, token)


@router.post("/logout-all", status_code=204)
def logout_all(db: DbDep, auth_form: AuthFormDep):
    user = validate_credentials(db, auth_form.username, auth_form.password)
    revoke_all_refresh_tokens(db, user)
