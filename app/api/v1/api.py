from fastapi import APIRouter
# Updated to include the new users endpoint. Assuming the existing `from .. import users` is different.
from .endpoints import models, threat_intelligence, ml_models, settings, auth,users as users_v1_endpoint 
from .. import users as old_users_router  # users.py is in backend/app/api/ - aliasing to avoid name collision

# This is the main router for all v1 endpoints
api_v1_router = APIRouter()

# Include the models router
api_v1_router.include_router(
    models.router, prefix="/models", tags=["Models"]
)  # Changed tag for consistency
api_v1_router.include_router(
    threat_intelligence.router,
    prefix="/threat-intelligence",
    tags=["Threat Intelligence"],
)
api_v1_router.include_router(old_users_router.router, prefix="/users", tags=["Users"]) # Keep the old one for now
api_v1_router.include_router(ml_models.router, prefix="/ml-models", tags=["ML Models"])
api_v1_router.include_router(settings.router, prefix="/settings", tags=["Settings"])

# Include the new auth router
api_v1_router.include_router(auth.router, prefix="/auth", tags=["authentication"])

# Include the new users router from endpoints
api_v1_router.include_router(users_v1_endpoint.router, prefix="/users_v1", tags=["users_v1_endpoints"]) # Changed prefix and tag to avoid conflict for now


# Future v1 endpoints can be added here, for example:
# from .endpoints import other_v1_endpoint
# api_v1_router.include_router(other_v1_endpoint.router, prefix="/other", tags=["other"])
