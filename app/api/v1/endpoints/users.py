# backend/app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Any

from ....core.security import get_current_active_user  # For protecting the endpoint
from ....models.user import (
    User as UserModel,
)  # For dependency injection if needed by get_current_active_user
from ....schemas.user import User as UserSchema  # Pydantic schema for response
from ....services import user as user_service  # User service functions
from ....database import get_db

router = APIRouter()


@router.get("/", response_model=List[UserSchema])
async def read_users(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),  # Add upper limit for performance
    current_user: UserModel = Depends(get_current_active_user),  # Protect endpoint
):
    # In a real application, you might want to restrict this endpoint to admin/superusers.
    # For example:
    # if not current_user.is_superuser:
    #     raise HTTPException(status_code=403, detail="Not enough permissions")

    users = await user_service.get_users(db, skip=skip, limit=limit)
    return users


# Placeholder for other user-specific endpoints like get specific user by ID, update, delete by admin, etc.
# For example:
# @router.get("/{user_id}", response_model=UserSchema)
# async def read_user_by_id(
# user_id: int,
# db: AsyncSession = Depends(get_db),
# current_user: UserModel = Depends(get_current_active_user)
# ):
# if not current_user.is_superuser and current_user.id != user_id:
# raise HTTPException(status_code=403, detail="Not enough permissions")
#     user = await user_service.get_user(db, user_id=user_id)
# if user is None:
# raise HTTPException(status_code=404, detail="User not found")
# return user
