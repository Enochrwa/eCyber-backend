from fastapi import APIRouter, Request
import json
from pathlib import Path
from datetime import datetime

router = APIRouter()
DB_FILE = Path("blocked_ips.json")


@router.post("/update")
async def update_threat_intel(request: Request):
    data = await request.json()
    ip = data.get("ip")
    action = data.get("action")

    # Load DB
    if DB_FILE.exists():
        db = json.loads(DB_FILE.read_text())
    else:
        db = []

    db.append({"ip": ip, "action": action, "timestamp": datetime.utcnow().isoformat()})

    DB_FILE.write_text(json.dumps(db, indent=2))
    return {"status": "stored", "ip": ip}
