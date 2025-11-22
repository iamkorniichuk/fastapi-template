from typing import Annotated
from fastapi import Depends, status, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)

from app.core.dependencies import DbDep
from app.domains.errors import DomainError
from app.models.user import User
from app.services.auth import get_current_user


AuthCredentialsDep = Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]
AuthFormDep = Annotated[OAuth2PasswordRequestForm, Depends()]


def require_auth(
    db: DbDep,
    auth_credentials: AuthCredentialsDep,
) -> User:
    if auth_credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token missing"
        )

    access_token = auth_credentials.credentials
    try:
        return get_current_user(db, access_token)
    except DomainError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error))


RequireAuthDep = Annotated[User, Depends(require_auth)]
