# app/database.py
from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from .core.config import settings
import logging
from contextlib import asynccontextmanager,contextmanager

from .models.user import User
from .models.log import Log
from .models.threat import ThreatLog
from .models.network import NetworkEvent
from .models.packet import Packets
from .models.firewall import FirewallLog, FirewallRule
from .models.ids_rule import IDSRule
from .models.config import AppConfig
from .models.system import SystemLog
from .models.ips import IPSRule, IPSEvent
from .models.base import Base


logger = logging.getLogger(__name__)
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./security.db"

# Create async engine
engine = create_async_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    poolclass=NullPool,
    connect_args=(
        {"check_same_thread": False}
        if "sqlite" in settings.SQLALCHEMY_DATABASE_URL
        else {}
    ),
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

# at top, alongside your async engine...
SyncSessionLocal = sessionmaker(
    bind=engine.sync_engine, autocommit=False, autoflush=False, expire_on_commit=False
)




@contextmanager
def get_sync_db():
    db = SyncSessionLocal()
    try:
        yield db
        db.commit()
    except:
        db.rollback()
        raise
    finally:
        db.close()


async def init_db():
    """Initialize database tables in correct order"""
    async with engine.begin() as conn:
        # First pass: Create tables without foreign key dependencies
        await conn.run_sync(Base.metadata.create_all, tables=[
            User.__table__,
            AppConfig.__table__,
            SystemLog.__table__,
            IDSRule.__table__,
            FirewallRule.__table__,
        ])

        # Second pass: Create tables with foreign keys
        await conn.run_sync(Base.metadata.create_all, tables=[
            Log.__table__,
            ThreatLog.__table__,
            NetworkEvent.__table__,
            Packets.__table__,
            FirewallLog.__table__,
            IPSEvent.__table__,
            IPSRule.__table__,
        ])
    logger.info("Database tables created in proper order")


@asynccontextmanager
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except IntegrityError as e:
            await session.rollback()
            logger.error(f"Database integrity error: {str(e)}")
            raise ValueError("Data validation failed") from e
        except SQLAlchemyError as e:
            await session.rollback()
            logger.error(f"Database operation failed: {str(e)}")
            logger.error(
                f"SQL Statement: {e.statement if hasattr(e, 'statement') else 'Unknown'}"
            )
            raise RuntimeError("Database operation failed") from e
        except Exception as e:
            await session.rollback()
            logger.error(f"Unexpected database error: {str(e)}")
            raise
        finally:
            await session.close()


@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in settings.SQLALCHEMY_DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
