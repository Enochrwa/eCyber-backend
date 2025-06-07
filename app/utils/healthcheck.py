from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import psutil
import os
import platform
from typing import Dict, Any

from app.database import get_db
from app.config import settings

router = APIRouter(tags=["Health"])


class HealthCheck:
    @staticmethod
    async def database_check(db: AsyncSession) -> Dict[str, Any]:
        try:
            await db.execute(text("SELECT 1"))
            return {"status": "healthy"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    @staticmethod
    def system_check() -> Dict[str, Any]:
        return {
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage("/").percent,
            "uptime": psutil.boot_time(),
            "process_uptime": psutil.Process(os.getpid()).create_time(),
        }

    @staticmethod
    def service_info() -> Dict[str, Any]:
        return {
            "service_name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "python_version": platform.python_version(),
            "system": platform.system(),
            "hostname": platform.node(),
        }


@router.get("/health", summary="Basic health check")
async def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@router.get("/health/database", summary="Database health check")
async def database_health(db: AsyncSession = Depends(get_db)):
    db_status = await HealthCheck.database_check(db)
    return JSONResponse(content=db_status)


@router.get("/health/system", summary="System health metrics")
async def system_health():
    system_status = HealthCheck.system_check()
    return JSONResponse(content=system_status)


@router.get("/health/full", summary="Complete health check")
async def full_health_check(db: AsyncSession = Depends(get_db)):
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "service": HealthCheck.service_info(),
        "database": await HealthCheck.database_check(db),
        "system": HealthCheck.system_check(),
        "dependencies": {
            "redis": "enabled" if settings.REDIS_URL else "disabled",
            "celery": "enabled" if settings.CELERY_BROKER_URL else "disabled",
        },
    }


@router.get("/health/version", summary="Service version information")
async def version_info():
    return HealthCheck.service_info()
