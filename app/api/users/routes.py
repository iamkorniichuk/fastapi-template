from fastapi import APIRouter, status

from app.api.auth.dependencies import RequireAuthDep
from app.schemas.users import UserResponse

router = APIRouter()


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
)
def me(user: RequireAuthDep):
    fields = set(UserResponse.__annotations__.keys())
    dump = user.model_dump(include=fields)
    return UserResponse(**dump)
