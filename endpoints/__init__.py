from fastapi import Depends, APIRouter
from internal.auth import get_current_active_user
from internal.log_calls import logging_dependency

router = APIRouter(
    dependencies=[Depends(get_current_active_user),
                  Depends(logging_dependency)]
)
