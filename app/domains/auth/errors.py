from app.domains.errors import DomainError


class AuthError(DomainError):
    pass


class TokenInvalidError(AuthError):
    pass


class TokenExpiredError(AuthError):
    pass


class TokenImmatureError(AuthError):
    pass


class TokenRevokedError(AuthError):
    pass


class TokenTypeInvalidError(AuthError):
    pass


class TokenPayloadInsufficientError(AuthError):
    pass
