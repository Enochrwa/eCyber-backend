from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int  # Added for convenience
    is_2fa_required: bool = False  # Added for 2FA flow
    message: Optional[str] = None


class TokenData(BaseModel):
    username: Optional[str] = None
    scope: Optional[str] = None  # Added for 2FA temp token
