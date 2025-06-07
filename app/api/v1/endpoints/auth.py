# backend/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any, Optional
from datetime import timedelta

from ....core import security
from ....core.config import settings
from ....core.security import (
    get_current_active_user,
)  # Assuming UserInDB or similar schema from security.py
from ....schemas.token import (
    Token,
    TokenData,
)  # Token schema, might need creation if not existing
from ....schemas.user import User as UserSchema, UserCreate  # User schema
from ....schemas.auth import (  # Schemas for 2FA and password recovery - will need to be created
    TwoFactorSetupResponse,
    TwoFactorVerify,
    PasswordResetRequest,
    NewPasswordWithToken,
)
from ....services import user as user_service  # Renamed to avoid conflict
from ....models.user import User as UserModel  # UserModel for dependency injection
from ....database import get_db
import pyotp  # For generating QR code URI
from ....schemas.user import (
    UserInDB,
)

router = APIRouter()


# Helper function to generate QR code URI (could also be in services)
def generate_qr_code_uri(
    secret: str, username: str, issuer_name: str = "eCyberPlatform"
) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=issuer_name
    )


@router.post("/login", response_model=Token)
async def login_for_access_token(
    db: AsyncSession = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()
):
    user = await security.authenticate_user(
        db=db,
        username=form_data.username,
        password=form_data.password
          # Pass db_session to authenticate_user
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.is_two_factor_enabled:
        # User has 2FA enabled, return a temporary token or a specific response
        # indicating 2FA is required.
        # For simplicity here, let's return a message. A better way might be a custom status/token.
        # This part needs careful design for frontend to handle.
        # Let's return a special response that includes user_id or a temporary token to proceed with 2FA.
        # For now, let's return user_id and a message.
        return {
            "access_token": security.create_access_token(
                data={"sub": user.username, "scope": "2fa_required"}
            ),  # Temp token
            "token_type": "bearer",
            "message": "2FA required",
            "user_id": user.id,  # Send user ID to make it easier for frontend to call verify_2fa
            "is_2fa_required": True,
        }

    access_token_expires = security.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "is_2fa_required": False,
    }


@router.post("/login/verify-2fa", response_model=Token)
async def verify_2fa_and_login(
    user_id: int = Body(..., embed=True),  # Or get from temp token
    code: str = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
):
    # In a real scenario, you might use the temporary token from login step to get user_id/username
    # For now, directly using user_id passed from frontend.
    db_user = await user_service.get_user(db, user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not db_user.is_two_factor_enabled or not db_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled for this user",
        )

    is_valid = await user_service.verify_two_factor_code(
        db, user_id=db_user.id, code=code
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code"
        )

    access_token_expires = security.timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    access_token = security.create_access_token(
        data={"sub": db_user.username}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": db_user.id,
        "is_2fa_required": False,
    }


@router.post("/register", response_model=UserSchema)
async def register_user(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user_by_email = await user_service.get_user_by_email(db, email=user_in.email)
    if db_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    db_user_by_username = await user_service.get_user_by_username(
        db, username=user_in.username
    )
    if db_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    created_user = await user_service.create_user(db=db, user=user_in)
    return created_user


@router.post("/password-recovery/request-token", status_code=status.HTTP_200_OK)
async def request_password_recovery(
    payload: PasswordResetRequest,  # Pydantic model with email: str
    db: AsyncSession = Depends(get_db),
):
    token = await user_service.generate_password_reset_token(db, email=payload.email)
    if not token:
        # Still return 200 OK to prevent email enumeration
        pass
    # Here you would email the token to the user.
    # For this task, we assume email sending is handled elsewhere or will be added later.
    # Log or print token for testing if needed, but not in production.
    print(f"Password reset token for {payload.email}: {token}")  # For testing only
    return {
        "message": "If an account with that email exists, a password reset link has been sent."
    }


@router.post("/password-recovery/reset-password", status_code=status.HTTP_200_OK)
async def reset_password_with_new(
    payload: NewPasswordWithToken,  # Pydantic model with token: str, new_password: str
    db: AsyncSession = Depends(get_db),
):
    success = await user_service.reset_password_with_token(
        db, token=payload.token, new_password=payload.new_password
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )
    return {"message": "Password has been reset successfully."}


# --- 2FA Management Endpoints ---
@router.post("/2fa/generate-secret", response_model=TwoFactorSetupResponse)
async def generate_2fa_secret_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user),  # Protect this endpoint
):
    secret = await user_service.generate_two_factor_secret(db, user_id=current_user.id)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not generate 2FA secret",
        )

    qr_uri = generate_qr_code_uri(secret, current_user.username)
    return {"secret": secret, "qr_code_uri": qr_uri}


@router.post("/2fa/enable", status_code=status.HTTP_200_OK)
async def enable_2fa_endpoint(
    payload: TwoFactorVerify,  # Pydantic model with code: str
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user),
):
    if current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled."
        )

    if not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA secret not generated. Please generate a secret first.",
        )

    success = await user_service.enable_two_factor(
        db, user_id=current_user.id, code=payload.code
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code. Please try again.",
        )
    return {"message": "2FA enabled successfully."}


@router.post("/2fa/disable", status_code=status.HTTP_200_OK)
async def disable_2fa_endpoint(
    # Consider requiring password or 2FA code to disable for extra security
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user),
):
    if not current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not currently enabled.",
        )

    success = await user_service.disable_two_factor(db, user_id=current_user.id)
    if not success:  # Should not happen if user is found
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not disable 2FA.",
        )
    return {"message": "2FA disabled successfully."}


@router.get(
    "/me", response_model=UserInDB
)  # Keeping UserInDB for now, but should be User
async def read_users_me(
    current_user: UserInDB = Depends(
        get_current_active_user
    ),  # This should use a User model that reflects DB structure
):
    return current_user
