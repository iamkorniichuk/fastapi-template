from uuid import uuid4, UUID
from datetime import datetime
from pydantic import field_validator
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str = Field()
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.now)


class UserCreate(SQLModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_security(cls, value: str) -> str:
        from string import punctuation

        contains_symbol = any(char in punctuation for char in value)
        contains_digit = any(char.isdigit() for char in value)
        contains_uppercase = any(char.isupper() for char in value)
        contains_lowercase = any(char.islower() for char in value)

        if not contains_symbol:
            raise ValueError("Password must contain at least one symbol")
        if not contains_digit:
            raise ValueError("Password must contain at least one digit")
        if not contains_uppercase:
            raise ValueError("Password must contain at least one uppercase letter")
        if not contains_lowercase:
            raise ValueError("Password must contain at least one lowercase letter")

        return value


class UserRead(SQLModel):
    id: str
    username: str
    created_at: datetime
