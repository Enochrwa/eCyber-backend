# backend/app/tasks/autofill_task.py
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.database.autofill import DatabaseAutofiller
from app.database import get_db
import logging

logger = logging.getLogger(__name__)

async def run_autofill_task(interval: int = 300):  # 5 minutes by default
    """Background task to periodically populate the database with sample data"""
    while True:
        try:
            # Get a new async session for each iteration
            async with get_db() as db:
                try:
                    filler = DatabaseAutofiller(db)
                    await filler.autofill_all(count=5)  # Add 5 entries to each table
                except Exception as e:
                    logger.error(f"Error during autofill: {e}")
                    await db.rollback()
                    raise

        except Exception as e:
            logger.error(f"Autofill task error: {e}")
        
        await asyncio.sleep(interval)