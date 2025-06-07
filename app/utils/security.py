import time
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Optional, Dict, Any, Callable
import hmac
import hashlib
import secrets
import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta
from functools import wraps
import logging

logger = logging.getLogger(__name__)


# Security Configuration
class SecurityConfig:
    SECRET_KEY = secrets.token_urlsafe(64)
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    RATE_LIMIT = 100  # requests per minute
    CSP_DIRECTIVES = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline' cdn.jsdelivr.net",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
    }


# JWT Token Utilities
class TokenUtils:
    @staticmethod
    def create_access_token(
        data: dict, expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(
            to_encode, SecurityConfig.SECRET_KEY, algorithm=SecurityConfig.ALGORITHM
        )

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(
                token, SecurityConfig.SECRET_KEY, algorithms=[SecurityConfig.ALGORITHM]
            )
            return payload
        except InvalidTokenError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            return None

    @staticmethod
    def create_hmac_signature(message: str) -> str:
        return hmac.new(
            SecurityConfig.SECRET_KEY.encode(), message.encode(), hashlib.sha256
        ).hexdigest()


# Rate Limiter Middleware
class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app, max_requests: int = SecurityConfig.RATE_LIMIT, time_window: int = 60
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_counts = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        current_time = int(time.time())
        time_slot = current_time // self.time_window

        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = {}

        if time_slot not in self.request_counts[client_ip]:
            self.request_counts[client_ip][time_slot] = 1
        else:
            self.request_counts[client_ip][time_slot] += 1

        # Clean up old time slots
        for ts in list(self.request_counts[client_ip].keys()):
            if ts < time_slot - 1:  # Keep only current and previous window
                del self.request_counts[client_ip][ts]

        current_count = sum(self.request_counts[client_ip].values())

        if current_count > self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            response = Response(
                content="Too Many Requests",
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str((time_slot + 1) * self.time_window),
                },
            )
            return response

        response = await call_next(request)
        response.headers.update(
            {
                "X-RateLimit-Limit": str(self.max_requests),
                "X-RateLimit-Remaining": str(self.max_requests - current_count),
                "X-RateLimit-Reset": str((time_slot + 1) * self.time_window),
            }
        )
        return response


# Security Headers Middleware
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    # Content Security Policy
    csp = "; ".join([f"{k} {v}" for k, v in SecurityConfig.CSP_DIRECTIVES.items()])

    response.headers.update(
        {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": csp,
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
    )

    return response


# JWT Bearer Authentication
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            payload = TokenUtils.verify_token(credentials.credentials)
            if not payload:
                raise HTTPException(status_code=403, detail="Invalid or expired token.")
            request.state.user = payload
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")


# Role-Based Access Control Decorator
def role_required(required_roles: list):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            if not hasattr(request.state, "user"):
                raise HTTPException(status_code=403, detail="Not authenticated")

            user_roles = request.state.user.get("roles", [])
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(status_code=403, detail="Insufficient permissions")

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


# CSRF Protection (for forms)
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_csrf_token(token: str, session_token: str) -> bool:
    return hmac.compare_digest(token, session_token)


# Export middleware instances
rate_limiter = RateLimiterMiddleware
