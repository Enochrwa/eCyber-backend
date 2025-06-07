# backend/app/services/user.py
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from ..models.user import User
from ..schemas.user import UserCreate, UserUpdate
from ..core.security import get_password_hash
from datetime import datetime, timedelta
from typing import Optional
import pyotp
import secrets

# sqlalchemy.update and select are already imported via `from sqlalchemy import select, update, delete`


async def get_user(db: AsyncSession, user_id: int):
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalars().first()


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalars().first()


async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(select(User).where(User.username == username))
    return result.scalars().first()


async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(User).offset(skip).limit(limit))
    return result.scalars().all()


async def create_user(db: AsyncSession, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def update_user(db: AsyncSession, user_id: int, user: UserUpdate):
    # Get existing user
    db_user = await get_user(db, user_id)
    if not db_user:
        return None

    update_data = user.dict(exclude_unset=True)
    if "password" in update_data:
        hashed_password = get_password_hash(user.password)
        update_data["hashed_password"] = hashed_password
        del update_data["password"]

    # Update each field
    for field, value in update_data.items():
        setattr(db_user, field, value)
    db_user.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(db_user)
    return db_user


async def delete_user(db: AsyncSession, user_id: int):
    db_user = await get_user(db, user_id)
    if not db_user:
        return None

    await db.delete(db_user)
    await db.commit()
    return db_user


async def generate_two_factor_secret(db: AsyncSession, user_id: int) -> Optional[str]:
    user = await get_user(db, user_id)
    if not user:
        return None

    if user.two_factor_secret:
        # If a secret already exists, perhaps for re-setup, clear it first
        # Or decide if this should return an error or the existing one.
        # For now, let's generate a new one.
        pass

    secret = pyotp.random_base32()
    user.two_factor_secret = secret
    # Important: Do NOT set is_two_factor_enabled to True here.
    # That happens only after verification.
    await db.commit()
    await db.refresh(user)
    return secret


async def verify_two_factor_code(db: AsyncSession, user_id: int, code: str) -> bool:
    user = await get_user(db, user_id)
    if not user or not user.two_factor_secret:
        return False

    totp = pyotp.TOTP(user.two_factor_secret)
    return totp.verify(code)


async def enable_two_factor(db: AsyncSession, user_id: int, code: str) -> bool:
    user = await get_user(db, user_id)
    if not user or not user.two_factor_secret:
        return False  # Should have generated a secret first

    if await verify_two_factor_code(db, user_id, code):  # Re-use verification logic
        user.is_two_factor_enabled = True
        # Optional: Clear the secret if it's only stored temporarily until enabled,
        # but typically it's kept for future verifications.
        # For TOTP, the secret MUST be stored.
        await db.commit()
        await db.refresh(user)
        return True
    return False


async def disable_two_factor(db: AsyncSession, user_id: int) -> bool:
    user = await get_user(db, user_id)
    if not user:
        return False

    user.is_two_factor_enabled = False
    user.two_factor_secret = None  # Clear the secret
    await db.commit()
    await db.refresh(user)
    return True


async def generate_password_reset_token(db: AsyncSession, email: str) -> Optional[str]:
    user = await get_user_by_email(db, email)
    if not user:
        return None  # Or raise an error, but for security, often better to not reveal if email exists

    # Generate a secure token
    token = secrets.token_urlsafe(32)

    # For security, store a hash of the token if you want to verify it without storing the raw token.
    # However, for password reset, the token itself is usually sent to the user and then submitted back.
    # Storing the raw token temporarily is common here.
    user.password_reset_token = token
    user.password_reset_expires = datetime.utcnow() + timedelta(
        hours=1
    )  # Token valid for 1 hour

    await db.commit()
    await db.refresh(user)

    # In a real application, you would send an email to the user with this token.
    # For example: send_password_reset_email(user.email, token)
    return token  # Return the token for now (e.g., for testing or if email sending is separate)


async def reset_password_with_token(
    db: AsyncSession, token: str, new_password: str
) -> bool:
    # Find user by the reset token
    # This requires querying the User table for the token.
    # Make sure there's an efficient way to do this, e.g., if tokens are hashed, you'd need to hash the input token.
    # For now, assuming raw token is stored.

    # Need to fetch the user by token. select is already imported
    result = await db.execute(select(User).where(User.password_reset_token == token))
    user = result.scalars().first()

    if not user:
        return False  # Token not found

    if (
        user.password_reset_expires is None
        or user.password_reset_expires < datetime.utcnow()
    ):
        # Token expired, clear it
        user.password_reset_token = None
        user.password_reset_expires = None
        await db.commit()
        return False

    # Token is valid, update password
    user.hashed_password = get_password_hash(new_password)
    user.password_reset_token = None  # Invalidate the token
    user.password_reset_expires = None
    user.updated_at = datetime.utcnow()  # Update timestamp

    await db.commit()
    return True
