# backend/app/services/detection/rate_limiter.py
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio


class RateLimiter:
    def __init__(self, max_requests: int, time_window: timedelta):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_logs = defaultdict(list)

    def check_rate_limit(self, ip: str) -> bool:
        """Return True if IP exceeds rate limit"""
        now = datetime.now()
        self.request_logs[ip] = [
            t for t in self.request_logs[ip] if now - t < self.time_window
        ]
        self.request_logs[ip].append(now)
        return len(self.request_logs[ip]) > self.max_requests
