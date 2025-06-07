from fastapi import APIRouter, Request

router = APIRouter()
sinkhole_policies = []


@router.post("/v1/policies")
async def add_policy(request: Request):
    data = await request.json()
    sinkhole_policies.append(data)
    return {"status": "sinkholed", "client_ip": data.get("client_ip")}
