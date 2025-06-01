from contextlib import asynccontextmanager
from datetime import datetime
import asyncio
import logging
from scapy.all import get_if_list
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from multiprocessing import Queue, Manager
import multiprocessing
from queue import Full, Empty
import asyncio
import psutil

# Configuration
from app.core.config import settings
from app.middleware.blocker_middleware import BlocklistMiddleware
from app.api.v1.api import api_v1_router

# from app.api.v1.endpoints.threats import router as threat_router_v1
from app.services.prevention.app_blocker import ApplicationBlocker
from app.core.logger import setup_logger
from socket_events import get_socket_app
from app.services.system.monitor import SystemMonitor

# from app.services.detection.phishing_blocker import PhishingBlocker

# from app.services.system.malware_detection import activate_cyber_defense


# Database
from sqlalchemy.ext.asyncio import AsyncEngine
from app.database import engine, Base, AsyncSessionLocal, init_db


# Routers
from app.api import (
    users as user_router,
    network as network_router,
    auth as auth_router,
    threats as threat_router,
    models as ml_models_router,
    system as system_router,
    admin as admin_router,
)
from app.api.v1.endpoints.threats import router as ml_threats
from api.firewall_api import router as firewall_router
from api.threat_intel_api import router as intel_router
from api.nac_api import router as nac_router
from api.dns_api import router as dns_router
from api.ml_models_api import router as ml_models_api_router  # Added for ML models API
from app.utils.report import (
    get_24h_network_traffic,
    get_daily_threat_summary,
    handle_network_history,
)

# from app.api.ips import get_ips_engine

# Services
from app.services.monitoring.sniffer import PacketSniffer
from app.services.detection.signature import SignatureEngine

# from app.services.detection.ids_signature import IdsSignatureEngine
from app.services.ips.engine import EnterpriseIPS, ThreatIntel

# from app.services.ips.adapter import IPSPacketAdapter
from app.services.prevention.firewall import FirewallManager

# from app.services.tasks.autofill_task import run_autofill_task

# Socket.IO
from sio_instance import sio
from packet_sniffer_service import PacketSnifferService
from packet_sniffer_events import PacketSnifferNamespace
from malware_events_namespace import MalwareEventsNamespace  # Add this

# from socket_events import start_event_emitter

# Logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
setup_logger("main", "INFO")
logger = logging.getLogger(__name__)

###VULNERABILITY
# scanner = VulnerabilityScanner(sio)
# val_blocker = ThreatBlocker(sio)


async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Initialize FastAPI app first
    app = FastAPI(
        title=settings.PROJECT_NAME,
        docs_url="/api/docs" if settings.DOCS else None,
        redoc_url=None,
    )

    # Initialize database
    try:
        if isinstance(engine, AsyncEngine):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        else:
            raise RuntimeError("Database engine is not asynchronous")
    except Exception as e:
        logger.critical(f"Database initialization failed: {str(e)}")
        raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan for startup and shutdown events."""
        await init_db()
        logger.info("🚀 Starting CyberWatch Security System")
        logger.info("Initializing background services...")

        # Initialize services
        firewall = FirewallManager(sio)
        signature_engine = SignatureEngine(sio)
        # ids_signature_engine = IdsSignatureEngine(sio)
        blocker = ApplicationBlocker(sio)

        # Initialize packet components INDEPENDENTLY
        manager = Manager()
        sio_queue = manager.Queue(maxsize=10000)
        output_queue = Queue()
        # ips_queue = manager.Queue(maxsize=10000)
        sniffer_namespace = PacketSnifferNamespace("/packet_sniffer", sio_queue)
        sio.register_namespace(sniffer_namespace)

        malware_events_ns = MalwareEventsNamespace("/malware_events")
        sio.register_namespace(malware_events_ns)
        logger.info("Registered /malware_events namespace for EMPDRS communication.")

        intel = ThreatIntel()
        await intel.load_from_cache()
        asyncio.create_task(intel.fetch_and_cache_feeds())
        ips = EnterpriseIPS(
            "rules.json",
            sio,
            intel,
            multiprocessing.cpu_count(),
            sio_queue,
            output_queue,
        )

        sniffer = PacketSniffer(sio_queue)

        sniffer_service = PacketSnifferService(sio, sio_queue)

        # loop = asyncio.get_event_loop()  # Get current loop
        monitor = SystemMonitor(sio)
        # cyber_defender = activate_cyber_defense(monitor)

        # phishing_blocker = PhishingBlocker(sio)
        # phishing_blocker = PhishingBlocker(sio)  # Initialize PhishingBlocker
        # logger.info("PhishingBlocker initialized.")

        # Initialize IPS Adapter
        # ips_adapter = IPSPacketAdapter(ips)
        # await ips_adapter.start()

        # Start database autofill task
        # autofill_task = asyncio.create_task(run_autofill_task(interval=300))

        # Store services in app state

        app.state.firewall = firewall
        app.state.signature_engine = signature_engine
        # app.state.ids_signature_engine = ids_signature_engine
        # app.state.phishing_blocker = (
        #     phishing_blocker  # Store PhishingBlocker in app state
        # )
        # app.state.ips_engine = ips
        # app.state.ips_adapter = ips_adapter
        app.state.db = AsyncSessionLocal
        # app.state.autofill_task = autofill_task
        app.state.blocker = blocker

        # emitter_task = asyncio.create_task(start_event_emitter())  # Pass the factory
        # app.state.emitter_task = emitter_task

        try:
            # loop = asyncio.get_running_loop()
            # await loop.run_in_executor(None, sniffer.start, "Wi-Fi")
            await sniffer_service.start()
            await sniffer.start("Wi-Fi")
            await monitor.start()
            await ips.start()
            logger.info("System monitoring started")
            # Start packet sniffer with IPS integration

            # Start IPS updates task
            # asyncio.create_task(ips_updates_task(ips))

            # Emit periodic summary
            # @sio.on("request_daily_summary")
            # async def _on_request_summary(sid):
            #     try:
            #         if not monitor.data_queue.empty():
            #             stats = monitor.data_queue.get_nowait()
            #             net24 = get_24h_network_traffic(stats)
            #             threats = get_daily_threat_summary(monitor)
            #             await sio.emit(
            #                 "daily_summary",
            #                 {"network24h": net24, "threatSummary": threats},
            #                 to=sid,
            #             )
            #     except Empty:
            #         pass

            yield

        finally:
            # Shutdown tasks
            logger.info("🛑 Gracefully shutting down...")

            # if hasattr(app.state, "phishing_blocker") and app.state.phishing_blocker:
            #     logger.info("Stopping PhishingBlocker...")
            #     # PhishingBlocker.stop() is an async method
            #     await app.state.phishing_blocker.stop()
            #     logger.info("PhishingBlocker stopped.")

            if monitor:
                await monitor.stop()
            if sniffer:  # sniffer.stop() is synchronous
                # To avoid blocking, it should ideally be run in an executor if it's long,
                # or made async. For now, calling it as is.
                logger.info("Stopping PacketSniffer...")
                sniffer.stop()
                logger.info("PacketSniffer stopped.")
            if sniffer_service:  # sniffer_service.stop() is async
                await sniffer_service.stop()

            # await ips_adapter.stop()
            # autofill_task.cancel()
            await engine.dispose()  # Dispose DB engine
            if ips:  # ips.stop() is async
                await ips.stop()
            # health_status = {
            #             "ips_queue_size": ips.input_queue.qsize(),
            #             "sniffer_packets": sniffer.packet_counter.value,
            #             "memory_usage": psutil.virtual_memory().percent,
            #             "timestamp": datetime.utcnow().isoformat()
            #         }
            # await sio.emit("system_health", health_status)

            # emitter_task.cancel()
            # scanner.stop_silent_monitor()

    # Set the lifespan after app creation
    app.router.lifespan_context = lifespan

    # Configure CORS first to ensure frontend access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add other middlewares
    # app.add_middleware(HTTPSRedirectMiddleware)
    # app.add_middleware(
    #     BlocklistMiddleware,
    #     blocker=(
    #         app.state.blocker
    #         if hasattr(app.state, "blocker")
    #         else ApplicationBlocker(sio)
    #     ),
    # )

    # Register routers
    app.include_router(user_router.router, prefix="/api/users", tags=["Users"])
    app.include_router(network_router.router, prefix="/api/network", tags=["Network"])
    app.include_router(auth_router.router, prefix="/api/auth", tags=["Auth"])
    # app.include_router(threat_router_v1, prefix="/api/v1/threats", tags=["Threats"])
    app.include_router(threat_router.router, prefix="/api/threats", tags=["Threats"])
    app.include_router(system_router.router, prefix="/api/system", tags=["System"])
    app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])
    app.include_router(api_v1_router, tags=["APIv1"])
    app.include_router(
        ml_models_router.router, prefix="/api/v1/models", tags=["models"]
    )  # Added for ML models
    # app.include_router(ids_router.router, prefix="/api/ids", tags=["IDS"])
    app.include_router(firewall_router, prefix="/firewall")
    app.include_router(intel_router, prefix="/intel")
    app.include_router(nac_router, prefix="/nac")
    app.include_router(dns_router, prefix="/dns")
    # Include the ML Models API router

    # Health check endpoint
    @app.get("/api/health", include_in_schema=False)
    async def health_check():
        return {"status": "ok"}

    # Mount Socket.IO app
    socket_app = get_socket_app(app)
    app.mount("/socket.io", socket_app)

    return app


# Socket.IO events
@sio.event
async def connect(sid, environ):
    pass
    # interfaces = get_if_list()
    # await sio.emit("interfaces", interfaces, to=sid)
    # PROD_CLEANUP: logger.info(f"Client connected: {sid[:8]}...")


# @sio.on("get_interfaces")
# async def get_interfaces(sid):
#     interfaces = get_if_list()
#     await sio.emit("interfaces", interfaces, to=sid)


# @sio.event
# async def disconnect(sid):
#     # PROD_CLEANUP: logger.info(f"Client disconnected: {sid[:8]}...")


# Hypercorn entry point
if __name__ == "__main__":
    import hypercorn.asyncio
    from hypercorn.config import Config

    config = Config()
    config.bind = ["127.0.0.1:8000"]
    config.use_reloader = True

    async def run():
        app = await create_app()  # Properly await the app creation
        await hypercorn.asyncio.serve(app, config)

    try:

        asyncio.run(run())

    except KeyboardInterrupt:
        pass
