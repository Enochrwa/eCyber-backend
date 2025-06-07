from fastapi import APIRouter, HTTPException
from ....services.threat_intelligence_service import ThreatIntelligenceService
from pydantic import BaseModel
from typing import List, Optional, Any

router = APIRouter()
threat_intelligence_service = ThreatIntelligenceService()


# Pydantic Models for API responses
class FeedStatus(BaseModel):
    id: str
    name: str
    status: str
    entries: int
    last_updated: Optional[str] = None
    source_url: Optional[str] = None
    is_subscribed: (
        bool  # Ensure this is not optional or defaulted here for clarity in response.
    )


class EmergingThreat(BaseModel):
    type: str
    id: Optional[str] = None
    summary: Optional[str] = None
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    threat_type: Optional[str] = None
    source: str
    published: Optional[str] = None
    last_seen: Optional[str] = None


class SubscriptionResponse(BaseModel):
    feed_id: str
    subscribed: bool  # Renamed from is_subscribed to match service logic return key


class SubscriptionRequest(BaseModel):
    is_subscribed: bool


class RefreshResponse(BaseModel):
    feed_id: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    message: Optional[str] = None
    last_updated: Optional[str] = None
    entry_count: Optional[int] = None


@router.get("/emerging-threats", response_model=List[EmergingThreat])
async def get_emerging_threats_endpoint():
    try:
        return threat_intelligence_service.get_emerging_threats()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get emerging threats: {str(e)}"
        )


@router.get("/feeds", response_model=List[FeedStatus])
async def list_feeds_endpoint():
    try:
        return threat_intelligence_service.get_feeds()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list feeds: {str(e)}")


# Use response_model=FeedStatus for subscribe endpoint as service returns the updated feed status
@router.post("/feeds/{feed_id}/subscribe", response_model=FeedStatus)
async def subscribe_to_feed_endpoint(
    feed_id: str, subscription_request: SubscriptionRequest
):
    try:
        # The service method now returns the updated feed status or an error dict
        result = threat_intelligence_service.update_feed_subscription(
            feed_id, subscription_request.is_subscribed
        )
        if isinstance(result, dict) and "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        # Ensure the result matches the FeedStatus model
        # The service's get_feeds() and update_feed_subscription() should be consistent
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        # logger.error(f"Error in subscribe_to_feed_endpoint for {feed_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update subscription for feed {feed_id}: {str(e)}",
        )


@router.post("/feeds/{feed_id}/refresh", response_model=RefreshResponse)
async def refresh_feed_endpoint(feed_id: str):
    try:
        result = threat_intelligence_service.refresh_feed_data(feed_id)
        # Result is a dictionary like:
        # {"feed_id": feed_id, "status": "refreshed", "last_updated": last_updated_ts, "entry_count": ...}
        # OR {"feed_id": feed_id, "status": "error", "error": ...}
        # OR {"feed_id": feed_id, "status": "skipped", "message": ...}

        if result.get("status") == "error":
            if "not recognized" in result.get("error", ""):
                raise HTTPException(status_code=404, detail=result.get("error"))
            return RefreshResponse(**result)  # Map directly if keys match
        elif result.get("status") == "skipped":
            return RefreshResponse(
                feed_id=feed_id,
                status="skipped",
                message=result.get("message", "Skipped for unspecified reason"),
            )
        elif result.get("status") == "refreshed":
            return RefreshResponse(
                feed_id=feed_id,
                status="refreshed",
                message=f"Feed '{feed_id}' data refreshed successfully.",
                last_updated=result.get("last_updated"),
                entry_count=result.get("entry_count"),
            )
        # Fallback for unexpected result structure
        return RefreshResponse(
            feed_id=feed_id,
            status="unknown",
            error="Unknown result from refresh operation",
        )

    except HTTPException as http_exc:  # Re-raise HTTP exceptions
        raise http_exc
    except Exception as e:
        # logger.error(f"Unhandled exception in refresh_feed_endpoint for {feed_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred while refreshing feed {feed_id}: {str(e)}",
        )
