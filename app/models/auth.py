from uuid import UUID
from datetime import datetime
from sqlmodel import Field, SQLModel


class RefreshToken(SQLModel, table=True):
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True)
    hashed_token: str = Field()
    expires_at: datetime = Field()
    created_at: datetime = Field(default_factory=datetime.now)
    is_revoked: bool = Field(default=False)
