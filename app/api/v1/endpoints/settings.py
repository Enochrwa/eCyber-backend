from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class GeneralSettings(BaseModel):
    notification_email: str
    update_frequency: str
    data_retention_days: int


@router.get("/general", response_model=GeneralSettings)
async def get_general_settings():
    """
    Retrieve mock general system settings.
    """
    return GeneralSettings(
        notification_email="admin@ecyber.com",
        update_frequency="daily",
        data_retention_days=90,
    )
