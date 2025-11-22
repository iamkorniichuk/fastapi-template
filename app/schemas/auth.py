from sqlmodel import SQLModel


class RefreshTokenRequest(SQLModel):
    refresh_token: str


class AuthTokenResponse(SQLModel):
    access_token: str
    refresh_token: str
