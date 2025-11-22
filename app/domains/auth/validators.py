from typing import Any, cast

from .entities import AccessTokenPayload, RefreshTokenPayload
from .errors import TokenPayloadInsufficientError, TokenTypeInvalidError


def _validate_token_payload(
    payload: dict, required_fields: set[str], expected_type: str
) -> dict[str, Any]:
    if not required_fields.issubset(payload):
        missing_fields = required_fields - payload.keys()
        raise TokenPayloadInsufficientError(
            f"Token payload must also contain these fields: {missing_fields}"
        )

    token_type = payload.get("typ")
    if token_type != expected_type:
        raise TokenTypeInvalidError(
            f"Token must be of type `{expected_type}`, instead of `{token_type}`"
        )

    return payload


def validate_access_token_payload(payload: dict) -> AccessTokenPayload:
    required_fields = {"sub", "iat", "exp", "typ"}
    payload = _validate_token_payload(payload, required_fields, expected_type="access")
    return cast(AccessTokenPayload, payload)


def validate_refresh_token_payload(payload: dict) -> RefreshTokenPayload:
    required_fields = {"jti", "sub", "iat", "exp", "typ"}
    payload = _validate_token_payload(payload, required_fields, expected_type="refresh")
    return cast(RefreshTokenPayload, payload)
