from typing import TypedDict


class AccessTokenPayload(TypedDict):
    sub: str
    iat: float
    exp: float
    typ: str


class RefreshTokenPayload(TypedDict):
    jti: str
    sub: str
    iat: float
    exp: float
    typ: str


class AuthTokens(TypedDict):
    refresh_token: str
    access_token: str
