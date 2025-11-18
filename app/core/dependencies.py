from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session

from app.core.db import get_db


DbDep = Annotated[Session, Depends(get_db)]
AuthFormDep = Annotated[OAuth2PasswordRequestForm, Depends()]
