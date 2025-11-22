from fastapi import APIRouter, HTTPException, status

from app.core.dependencies import DbDep
from app.domains.errors import DomainError
from app.schemas.auth import AuthTokenResponse, RefreshTokenRequest
from app.services.auth import (
    generate_tokens,
    login_user,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
    signup_user,
    validate_refresh_token,
)

from .dependencies import AuthFormDep

router = APIRouter()


@router.post(
    "/signup",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def signup(db: DbDep, auth_form: AuthFormDep):
    try:
        user = signup_user(db, auth_form.username, auth_form.password)
    except DomainError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    tokens = generate_tokens(db, user.id)
    return AuthTokenResponse(**tokens)


@router.post(
    "/login",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_200_OK,
)
def login(db: DbDep, auth_form: AuthFormDep):
    try:
        user = login_user(db, auth_form.username, auth_form.password)
    except DomainError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    tokens = generate_tokens(db, user.id)
    return AuthTokenResponse(**tokens)


@router.post(
    "/refresh",
    response_model=AuthTokenResponse,
    status_code=status.HTTP_200_OK,
)
def refresh(db: DbDep, data: RefreshTokenRequest):
    try:
        token = validate_refresh_token(db, data.refresh_token)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error.args)

    user_id = token.user_id
    tokens = generate_tokens(db, user_id)
    return AuthTokenResponse(**tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(db: DbDep, data: RefreshTokenRequest):
    try:
        token = validate_refresh_token(db, data.refresh_token)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error.args)

    revoke_refresh_token(db, token)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(db: DbDep, auth_form: AuthFormDep):
    try:
        user = login_user(db, auth_form.username, auth_form.password)
    except DomainError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    revoke_all_refresh_tokens(db, user)
