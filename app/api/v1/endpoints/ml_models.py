from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()


class ModelAccuracy(BaseModel):
    model_name: str
    accuracy: float
    last_trained: datetime


@router.get("/accuracy", response_model=ModelAccuracy)
async def get_model_accuracy():
    """
    Retrieve mock accuracy data for an ML model.
    """
    return ModelAccuracy(
        model_name="Main Anomaly Detector",
        accuracy=0.997,
        last_trained=datetime.fromisoformat("2023-10-26T10:00:00Z"),
    )
