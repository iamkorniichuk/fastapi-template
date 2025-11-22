from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.db import init_db
from app.core.settings import get_settings
from app.api.auth import routes as auth_routes
from app.api.users import routes as users_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


title = get_settings().app.title
description = get_settings().app.description
version = get_settings().app.version
app = FastAPI(
    title=title,
    description=description,
    version=version,
    lifespan=lifespan,
)

app.include_router(auth_routes.router, prefix="/auth", tags=["Auth"])
app.include_router(users_routes.router, prefix="/users", tags=["Users"])
