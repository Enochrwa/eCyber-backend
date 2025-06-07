from fastapi import APIRouter, Request

router = APIRouter()
nac_quarantine_log = []


@router.post("/quarantine")
async def quarantine_nac(request: Request):
    data = await request.json()
    nac_quarantine_log.append(data)
    return {"status": "quarantined", "ip": data.get("ip_address")}
