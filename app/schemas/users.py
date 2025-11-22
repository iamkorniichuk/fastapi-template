from datetime import datetime
from sqlmodel import SQLModel


class UserResponse(SQLModel):
    username: str
    is_active: bool
    created_at: datetime
