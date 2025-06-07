from pydantic import BaseModel


class TwoFactorSecretResponse(BaseModel):
    secret_key: str
    qr_code_uri: str


class TwoFactorEnableRequest(BaseModel):
    code: str


class TwoFactorVerifyRequest(BaseModel):
    user_id: int  # Or could be derived from token if preferred by design
    code: str
