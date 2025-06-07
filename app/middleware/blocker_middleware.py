# backend/app/middleware/blocker_middleware.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime

class BlocklistMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, blocker):
        super().__init__(app)
        self.blocker = blocker

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        
        if client_ip and await self.blocker.is_blocked(client_ip):
            await self.blocker.emit_block_event(
                "BLOCK_ATTEMPT",
                client_ip,
                None,
                None,
                {"path": request.url.path}
            )
            raise HTTPException(
                status_code=403,
                detail="Your IP address has been temporarily blocked"
            )
        
        response = await call_next(request)
        return response