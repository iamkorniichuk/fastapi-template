from datetime import timedelta
from functools import lru_cache
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class DbSettings(BaseModel):
    connect_url: str = Field(
        title="Database Connection String",
        description=(
            "The full database connection string in the following format:\n"
            "   `dialect[+driver]://[user:password@]host/dbname[?key=value..]`,\n"
        ),
        examples=[
            "postgresql+psycopg2://scott:tiger@localhost/test",
            "mysql+mysqldb://scott:tiger@hostname/dbname",
            "sqlite:///local.db",
        ],
    )


class SecuritySettings(BaseModel):
    secret_key: str = Field(
        title="Secret Key",
        description="SA cryptographically secure key used for signing and verifying tokens.\n"
        "Preferrably, generate it using following command:\n"
        "  `openssl rand -hex 32`",
        examples=[
            "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
            "562ae6d779755b412151676a84c4b9500ce86c38ec60fd11b176773ed2c1fb66",
        ],
    )
    encode_algorithm: str = Field(
        default="HS256",
        title="Encoding Algorithm",
        description="The algorithm used for encoding and decoding security tokens.",
        examples=[
            "HS256",
            "RS256",
        ],
    )
    access_token_ttl: timedelta = Field(
        default=timedelta(minutes=15),
        title="Access Token Expiration",
        description="The time after which an issued access token will expire.",
        examples=[
            "P0DT0H15M0S",
            "P0DT1H0M0S",
        ],
    )


class AppSettings(BaseModel):
    title: str = Field(
        default="FastAPI",
        title="Application Title",
        description="The title, displayed in the API documentation.",
    )
    description: str = Field(
        default="",
        title="Application Description",
        description="The description, displayed in the API documentation.",
    )
    version: str = Field(
        default="0.1.0",
        title="Application Version",
        description="Version string, displayed in the API documentation.",
        examples=[
            "1.2.3",
            "0.8.1",
            "2.0.23",
        ],
    )


class Settings(BaseSettings):
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"
        extra = "forbid"

    db: DbSettings
    security: SecuritySettings
    app: AppSettings


@lru_cache
def get_settings():
    return Settings()  # type: ignore[call-arg]
