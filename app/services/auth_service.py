import pyotp  # Added pyotp import
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from backend.app.models.user import User  # User model is already imported
from backend.app.schemas.user import UserCreate
from backend.app.core.security import get_password_hash


async def create_user(user_data: UserCreate, db: AsyncSession) -> User:
    """
    Creates a new user.
    """
    # Check if user already exists
    stmt = select(User).where(
        (User.username == user_data.username) | (User.email == user_data.email)
    )
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    # Hash the password
    hashed_password = get_password_hash(user_data.password)

    # Create new user instance
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        is_active=(
            user_data.is_active if user_data.is_active is not None else True
        ),  # Default to True if not provided
        is_superuser=(
            user_data.is_superuser if user_data.is_superuser is not None else False
        ),  # Default to False
    )

    # Add to session and commit
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


async def generate_two_factor_secret(user: User, db: AsyncSession) -> dict:
    """
    Generates a new 2FA secret for the user.
    """
    secret = pyotp.random_base32()
    user.two_factor_secret = secret
    user.is_two_factor_enabled = False  # Explicitly set to False until verified

    db.add(user)
    await db.commit()
    await db.refresh(user)

    # issuer_name should ideally come from config
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="eCyberApp"
    )

    return {"secret_key": secret, "qr_code_uri": otp_uri}


async def enable_two_factor_authentication(
    code: str, user: User, db: AsyncSession
) -> bool:
    """
    Enables 2FA for the user if the provided code is valid.
    """
    if not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA secret not generated for this user yet.",
        )

    totp = pyotp.TOTP(user.two_factor_secret)

    if not totp.verify(code):
        return False

    user.is_two_factor_enabled = True
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return True


async def verify_two_factor_code_for_login(
    user_id: int, code: str, db: AsyncSession
) -> User:
    """
    Verifies the 2FA code for a user during login.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not user.is_two_factor_enabled or not user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not enabled for this user",
        )

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code"
        )

    return user


async def disable_two_factor_authentication(user: User, db: AsyncSession) -> bool:
    """
    Disables 2FA for the given user.
    """
    user.two_factor_secret = None
    user.is_two_factor_enabled = False

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return True
