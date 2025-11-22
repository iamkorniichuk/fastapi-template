class DomainError(Exception):
    pass


class NotFoundError(DomainError):
    pass


class AlreadyExistsError(DomainError):
    pass


class InvalidValueError(DomainError):
    pass
