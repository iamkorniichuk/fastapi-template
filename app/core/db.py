from sqlmodel import Session, SQLModel, create_engine

from app.core.settings import get_settings


url = get_settings().db.connect_url
engine = create_engine(url)


def init_db():
    SQLModel.metadata.create_all(engine)


def get_db():
    with Session(engine) as session:
        yield session
