# backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class NewPasswordRequest(BaseModel):
    token: str
    new_password: str



class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_code_uri: str


class TwoFactorVerify(BaseModel):
    code: str



class NewPasswordWithToken(BaseModel):
    token: str
    new_password: str
