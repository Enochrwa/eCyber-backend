import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

# Adjust import paths based on your project structure
from app.database import get_db
from app.schemas.threat_analysis import (
    ThreatAnalysisSummary,
    ThreatAnalysisTrends,
    PaginatedThreatAnalysisTableResponse,
    ThreatAnalysisDetailResponse,
)
from app.services import threat_analysis_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-analysis", tags=["Threat Analysis"])


@router.get("/summary", response_model=ThreatAnalysisSummary)
async def read_threat_summary(
    db: AsyncSession = Depends(get_db),
    threat_type: Optional[str] = Query(
        None, description="Filter summary by a specific threat type (e.g., 'Anomaly')"
    ),
):
    try:
        summary_data = await threat_analysis_service.get_threat_summary(
            db=db, threat_type_filter=threat_type
        )
        return summary_data
    except Exception as e:
        logger.error(
            f"Error fetching threat summary (filter: {threat_type}): {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Internal server error while fetching summary"
        )


@router.get("/trends", response_model=ThreatAnalysisTrends)
async def read_threat_trends(
    db: AsyncSession = Depends(get_db),
    threat_type: Optional[str] = Query(
        None, description="Filter trends by a specific threat type (e.g., 'Anomaly')"
    ),
):
    try:
        trends_data = await threat_analysis_service.get_threat_trends(
            db=db, threat_type_filter=threat_type
        )
        return trends_data
    except Exception as e:
        logger.error(
            f"Error fetching threat trends (filter: {threat_type}): {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Internal server error while fetching trends"
        )


@router.get("/threats", response_model=PaginatedThreatAnalysisTableResponse)
async def list_threats(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    sort_by: Optional[str] = Query(
        None, description="Field to sort by (e.g., 'timestamp', 'severity')"
    ),
    sort_desc: bool = Query(
        False, description="True for descending, False for ascending"
    ),
    threat_type_filter: Optional[str] = Query(
        None, description="Filter by threat type"
    ),
    start_date_filter: Optional[datetime] = Query(
        None,
        description="Filter by start date (ISO datetime format YYYY-MM-DDTHH:MM:SS)",
    ),
    end_date_filter: Optional[datetime] = Query(
        None, description="Filter by end date (ISO datetime format YYYY-MM-DDTHH:MM:SS)"
    ),
    verdict_filter: Optional[str] = Query(
        None, description="Filter by verdict (e.g., 'Malicious', 'Benign')"
    ),
):
    try:
        paginated_threats = await threat_analysis_service.list_threats_paginated(
            db=db,
            page=page,
            size=size,
            sort_by=sort_by,
            sort_desc=sort_desc,
            threat_type_filter=threat_type_filter,
            start_date_filter=start_date_filter,
            end_date_filter=end_date_filter,
            verdict_filter=verdict_filter,
        )
        return paginated_threats
    except Exception as e:
        logger.error(f"Error listing threats: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal server error while listing threats"
        )


@router.get("/threats/{threat_id}", response_model=ThreatAnalysisDetailResponse)
async def read_threat_detail(threat_id: str, db: AsyncSession = Depends(get_db)):
    try:
        detail = await threat_analysis_service.get_threat_detail(
            db=db, threat_id=threat_id
        )
        if detail is None:
            raise HTTPException(
                status_code=404, detail=f"Threat with ID {threat_id} not found"
            )
        return detail
    except HTTPException as http_exc:  # Re-raise HTTPException (like 404)
        raise http_exc
    except (
        ValueError
    ) as ve:  # Catch ValueError from service if threat_id is not a valid int
        logger.warning(f"Invalid threat ID format for '{threat_id}': {ve}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid threat ID format: {threat_id}. Must be an integer.",
        )
    except Exception as e:
        logger.error(
            f"Error fetching threat detail for ID {threat_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while fetching threat detail for ID {threat_id}",
        )
