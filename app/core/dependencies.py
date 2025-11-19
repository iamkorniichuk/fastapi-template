from typing import Annotated
from fastapi import Depends
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)
from sqlmodel import Session

from app.core.db import get_db
from app.models.user import User
from app.services.auth import get_current_user


DbDep = Annotated[Session, Depends(get_db)]
AuthFormDep = Annotated[OAuth2PasswordRequestForm, Depends()]
AuthCredentialsDep = Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer)]
UserDep = Annotated[User, Depends(get_current_user)]
