from fastapi import Request, Response
from fastapi.routing import APIRouter
from functools import wraps

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Summary,
    generate_latest,
    REGISTRY,
    CollectorRegistry,
)
from prometheus_client.multiprocess import MultiProcessCollector
import time
import os
import asyncio

from typing import Callable, Optional
from starlette.types import ASGIApp, Receive, Send, Scope
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Metrics"])

# Custom registry to support multiprocess
registry = CollectorRegistry()
MultiProcessCollector(registry)

# Application Metrics
REQUEST_COUNT = Counter(
    "app_request_count",
    "Total count of requests by method and path",
    ["method", "path", "status_code"],
    registry=registry,
)

REQUEST_LATENCY = Histogram(
    "app_request_latency_seconds",
    "Request latency in seconds",
    ["method", "path"],
    registry=registry,
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
)

REQUEST_SIZE = Summary(
    "app_request_size_bytes",
    "Request size in bytes",
    ["method", "path"],
    registry=registry,
)

RESPONSE_SIZE = Summary(
    "app_response_size_bytes",
    "Response size in bytes",
    ["method", "path"],
    registry=registry,
)

EXCEPTION_COUNT = Counter(
    "app_exception_count",
    "Total count of exceptions by type",
    ["exception_type"],
    registry=registry,
)

DATABASE_QUERY_TIME = Histogram(
    "app_db_query_duration_seconds",
    "Database query duration in seconds",
    ["query_type"],
    registry=registry,
)

SYSTEM_METRICS = Gauge(
    "app_system_metrics", "System resource metrics", ["metric_type"], registry=registry
)


# Metrics Middleware
class PrometheusMiddleware:
    def __init__(self, app: ASGIApp, filter_unwanted_paths: bool = True):
        self.app = app
        self.filter_unwanted = filter_unwanted_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        request = Request(scope)
        method = request.method
        path = request.url.path

        # Skip metrics endpoint and unwanted paths
        if self.filter_unwanted and (
            path.startswith("/metrics") or path.startswith("/health")
        ):
            return await self.app(scope, receive, send)

        start_time = time.time()
        request_size = 0

        # Calculate request size
        if "content-length" in request.headers:
            request_size = int(request.headers["content-length"])

        # Intercept response to capture metrics
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code = message["status"]
                process_time = time.time() - start_time
                response_size = 0

                if "content-length" in message.get("headers", []):
                    response_size = int(
                        next(v for k, v in message["headers"] if k == b"content-length")
                    )

                # Record metrics
                REQUEST_COUNT.labels(method, path, status_code).inc()
                REQUEST_LATENCY.labels(method, path).observe(process_time)
                REQUEST_SIZE.labels(method, path).observe(request_size)
                RESPONSE_SIZE.labels(method, path).observe(response_size)

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            EXCEPTION_COUNT.labels(type(e).__name__).inc()
            raise


# Setup function to be called from main.py
def setup_metrics(app: ASGIApp):
    app.add_middleware(PrometheusMiddleware)

    # Start background task to update system metrics
    async def update_system_metrics():
        import psutil

        while True:
            SYSTEM_METRICS.labels("cpu_usage").set(psutil.cpu_percent())
            SYSTEM_METRICS.labels("memory_usage").set(psutil.virtual_memory().percent)
            SYSTEM_METRICS.labels("disk_usage").set(psutil.disk_usage("/").percent)
            await asyncio.sleep(15)

    @app.on_event("startup")
    async def start_metrics_task():
        asyncio.create_task(update_system_metrics())


# Metrics endpoint
@router.get("/metrics", summary="Prometheus metrics endpoint")
async def metrics():
    return Response(content=generate_latest(registry), media_type="text/plain")


# Database query timer context manager
class DatabaseQueryTimer:
    def __init__(self, query_type: str):
        self.query_type = query_type
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            DATABASE_QUERY_TIME.labels(self.query_type).observe(duration)


# Decorator for tracking function execution
def track_function_metrics(name: Optional[str] = None):
    def decorator(func: Callable):
        metric_name = name or func.__name__
        counter = Counter(
            f"app_function_{metric_name}_count",
            f"Count of {metric_name} function calls",
            registry=registry,
        )
        summary = Summary(
            f"app_function_{metric_name}_duration_seconds",
            f"Duration of {metric_name} function calls",
            registry=registry,
        )

        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                counter.inc()
                with summary.time():
                    return await func(*args, **kwargs)

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                counter.inc()
                with summary.time():
                    return func(*args, **kwargs)

            return sync_wrapper

    return decorator
