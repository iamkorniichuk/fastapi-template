from typing import Any
import jwt

from app.core.settings import get_settings
from app.domains.auth.errors import (
    TokenInvalidError,
    TokenExpiredError,
    TokenImmatureError,
)


algorithm = get_settings().security.encode_algorithm
secret_key = get_settings().security.secret_key


def encode(payload: dict[str, Any]) -> str:
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode(token: str):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Token has expired")
    except jwt.ImmatureSignatureError:
        raise TokenImmatureError("Token is not yet valid")
    except (jwt.InvalidAlgorithmError, jwt.DecodeError):
        raise TokenInvalidError("Invalid token")

    return payload
