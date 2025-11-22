import string

from app.domains.errors import InvalidValueError


def validate_password_strength(password: str) -> str:
    length_valid = len(password) >= 8
    contains_symbol = any(char in string.punctuation for char in password)
    contains_digit = any(char.isdigit() for char in password)
    contains_uppercase = any(char.isupper() for char in password)
    contains_lowercase = any(char.islower() for char in password)

    if not length_valid:
        raise InvalidValueError("Password must be at least 8 characters long")
    if not contains_symbol:
        raise InvalidValueError("Password must contain at least one symbol")
    if not contains_digit:
        raise InvalidValueError("Password must contain at least one digit")
    if not contains_uppercase:
        raise InvalidValueError("Password must contain at least one uppercase letter")
    if not contains_lowercase:
        raise InvalidValueError("Password must contain at least one lowercase letter")

    return password
