# backend/app/api/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel  # Added for UserSummary

from ..database import get_db
from ..models.user import User  # Import the SQLAlchemy model
from ..schemas.user import UserCreate, UserInDB, UserUpdate
from ..services.user import get_user, get_users, create_user, update_user, delete_user
from ..services.user import (
    get_user,
    get_users,
    create_user,
    update_user,
    delete_user,
    get_user_by_email,
)

router = APIRouter()


@router.post("/", response_model=UserInDB)
async def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = await get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return await create_user(db=db, user=user)


@router.get("/", response_model=List[UserInDB])
async def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = await get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=UserInDB)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/{user_id}", response_model=UserInDB)
def update_existing_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    db_user = get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return update_user(db=db, user_id=user_id, user=user)


@router.delete("/{user_id}", response_model=UserInDB)
def delete_existing_user(user_id: int, db: Session = Depends(get_db)):
    db_user = get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return delete_user(db=db, user_id=user_id)


# Pydantic model for User Summary
class UserSummary(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int


@router.get("/summary", response_model=UserSummary)
async def get_user_summary(db: Session = Depends(get_db)):
    """
    Retrieve a summary of users.
    """
    total_users = db.query(User).count()
    admin_users = db.query(User).filter(User.is_superuser == True).count()
    standard_users = total_users - admin_users
    return UserSummary(
        total_users=total_users, admin_users=admin_users, standard_users=standard_users
    )
