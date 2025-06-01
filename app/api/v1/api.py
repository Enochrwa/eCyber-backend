from fastapi import APIRouter
from .endpoints import models

# This is the main router for all v1 endpoints
api_v1_router = APIRouter()

# Include the models router
api_v1_router.include_router(models.router, prefix="/models", tags=["models"])

# Future v1 endpoints can be added here, for example:
# from .endpoints import other_v1_endpoint
# api_v1_router.include_router(other_v1_endpoint.router, prefix="/other", tags=["other"])
