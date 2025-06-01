from fastapi import APIRouter, Request

router = APIRouter()
firewall_state = {"blocked": set(), "throttled": set(), "quarantined": set()}


@router.post("/{action}")
async def firewall_action(action: str, request: Request):
    data = await request.json()
    ip = data.get("ip")

    if action == "block":
        firewall_state["blocked"].add(ip)
    elif action == "unblock":
        firewall_state["blocked"].discard(ip)
    elif action == "throttle":
        firewall_state["throttled"].add(ip)
    elif action == "quarantine":
        firewall_state["quarantined"].add(ip)
    elif action == "unthrottle":
        firewall_state["throttled"].discard(ip)
    elif action == "unquarantine":
        firewall_state["quarantined"].discard(ip)
    else:
        return {"error": "unknown action"}

    return {"status": "ok", "action": action, "ip": ip}
