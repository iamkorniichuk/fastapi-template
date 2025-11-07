from fastapi import FastAPI

from app.core.settings import get_settings


title = get_settings().app.title
description = get_settings().app.description
version = get_settings().app.version
app = FastAPI(title=title, description=description, version=version)
