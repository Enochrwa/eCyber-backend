# backend/app/core/filters.py
import logging


class NoiseFilter(logging.Filter):
    """Filter out repetitive or low-priority logs"""

    def filter(self, record):
        # Skip SQLAlchemy table info checks
        if "PRAGMA main.table_info" in record.getMessage():
            return False

        # Skip Socket.IO emit messages
        if "emitting event" in record.getMessage():
            return False

        # Skip routine heartbeat messages
        if "heartbeat" in record.getMessage().lower():
            return False

        return True


def configure_filters():
    """Apply filters to all loggers"""
    noise_filter = NoiseFilter()

    # Apply to root logger
    logging.getLogger().addFilter(noise_filter)

    # Keep SQLAlchemy warnings and errors
    sql_logger = logging.getLogger("sqlalchemy")
    sql_logger.setLevel(logging.WARNING)
