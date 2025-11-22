from datetime import datetime
from uuid import UUID, uuid4

from app.core.settings import get_settings

from .entities import AccessTokenPayload, RefreshTokenPayload


access_token_ttl = get_settings().security.access_token_ttl
refresh_token_ttl = get_settings().security.refresh_token_ttl


def create_access_token_payload(user_id: UUID) -> AccessTokenPayload:
    issued_at = datetime.now()
    expires_at = issued_at + access_token_ttl
    return AccessTokenPayload(
        sub=user_id.hex,
        iat=issued_at.timestamp(),
        exp=expires_at.timestamp(),
        typ="access",
    )


def create_refresh_token_payload(user_id: UUID) -> RefreshTokenPayload:
    token_id = uuid4()
    issued_at = datetime.now()
    expires_at = issued_at + refresh_token_ttl
    return RefreshTokenPayload(
        jti=token_id.hex,
        sub=user_id.hex,
        iat=issued_at.timestamp(),
        exp=expires_at.timestamp(),
        typ="refresh",
    )
