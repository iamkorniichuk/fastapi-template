from pwdlib import PasswordHash


hasher = PasswordHash.recommended()


def hash(value: str) -> str:
    return hasher.hash(value)


def verify(value: str, hashed_value: str) -> bool:
    return hasher.verify(value, hashed_value)
