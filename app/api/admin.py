# backend/app/api/admin.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.services.database.autofill import DatabaseAutofiller
from app.database import get_db

router = APIRouter()


@router.post("/autofill", tags=["Admin"])
def trigger_autofill(count: int = 10, db: Session = Depends(get_db)):
    filler = DatabaseAutofiller(db)
    results = filler.autofill_all(count=count)
    return {"message": f"Added {len(results)} records", "details": results}
