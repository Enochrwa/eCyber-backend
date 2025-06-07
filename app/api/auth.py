# backend/app/api/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import pyotp  # Added
from sqlalchemy.ext.asyncio import AsyncSession  # Added

from ..core.security import (
    authenticate_user,
    create_access_token,
    get_current_active_user,  # Will be replaced by get_current_user_for_2fa for one endpoint
    get_current_user_for_2fa,  # Added
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from ..schemas.user import (
    UserInDB,
)  # UserInDB might be replaced by User model from models.user
from ..schemas.token import Token  # Ensure Token schema is appropriate
from ..schemas.auth import TwoFactorVerify  # Changed from TwoFactorVerificationRequest
from ..database import get_db  # Added
from ..models.user import User  # Added

router = APIRouter()


@router.post(
    "/login"
)  # response_model removed to allow for different response structures
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),  # Added
):
    user = await authenticate_user(
        db, form_data.username, form_data.password
    )  # Added db
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.is_two_factor_enabled:
        access_token_expires = timedelta(minutes=5)  # Short expiry for 2FA token
        access_token = create_access_token(
            data={"sub": user.username, "scope": "2fa_required", "user_id": user.id},
            expires_delta=access_token_expires,
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "is_2fa_required": True,
            "user_id": user.id,
        }
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},  # No "2fa_required" scope
            expires_delta=access_token_expires,
        )
        return {"access_token": access_token, "token_type": "bearer"}


@router.post("/verify-2fa", response_model=Token)
async def verify_2fa_login(
    request_data: TwoFactorVerify,  # Changed from TwoFactorVerificationRequest
    current_user: User = Depends(get_current_user_for_2fa),  # Changed to User model
    db: AsyncSession = Depends(get_db),
):
    # current_user here is the user object fetched based on the temporary 2FA token.
    # The get_current_user_for_2fa dependency will ensure the token had the '2fa_required' scope.

    user = await db.get(User, current_user.id)  # Fetch the full User model instance
    if not user or not user.is_two_factor_enabled or not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled or user not found.",
        )

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(request_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If code is valid, issue a new token without 2FA scope
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires  # Regular scope
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get(
    "/me", response_model=UserInDB
)  # Keeping UserInDB for now, but should be User
async def read_users_me(
    current_user: UserInDB = Depends(
        get_current_active_user
    ),  # This should use a User model that reflects DB structure
):
    return current_user


@router.post("/logout")
async def logout():
    return {"message": "Successfully logged out"}
