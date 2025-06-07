import geoip2.database
import logging
from typing import Optional
from pathlib import Path

# Assuming app.core.config.settings might exist but not strictly relying on it here
# as per instructions to use a placeholder if settings.GEOIP_DATABASE_PATH is not explicitly available.
# from app.core.config import settings

logger = logging.getLogger(__name__)

# Path to the GeoLite2 database file.
# IMPORTANT ASSUMPTION:
# This path is assumed to be "data/GeoLite2-Country.mmdb" relative to the project root.
# For this utility to function, the 'geoip2' library must be installed (e.g., `pip install geoip2`)
# and the GeoLite2-Country.mmdb file must be downloaded from MaxMind and placed in the 'data/' directory.
# If `settings.GEOIP_DATABASE_PATH` were available and configured, it would be used like:
# GEOIP_DATABASE_PATH = Path(settings.GEOIP_DATABASE_PATH)
GEOIP_DATABASE_PATH = Path("data/GeoLite2-Country.mmdb")

_geoip_reader: Optional[geoip2.database.Reader] = None

def _initialize_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        if not GEOIP_DATABASE_PATH.exists():
            logger.error(
                f"GeoIP database file not found at {GEOIP_DATABASE_PATH}. "
                "Please download it from MaxMind and place it in the correct location. "
                "GeoIP lookups will fail."
            )
            _geoip_reader = None # Ensure it's None if file not found before even trying to open
            return

        try:
            logger.info(f"Initializing GeoIP reader with database: {GEOIP_DATABASE_PATH}")
            _geoip_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH)) # Reader expects string path
            logger.info("GeoIP reader initialized successfully.")
        except FileNotFoundError: # Should be caught by pre-check, but as a safeguard
            logger.error(f"GeoIP database file not found at {GEOIP_DATABASE_PATH}. GeoIP lookups will fail.")
            _geoip_reader = None
        except geoip2.errors.GeoIP2Error as e: # Catch specific geoip2 errors
            logger.error(f"Error initializing GeoIP reader (GeoIP2Error): {e} for database {GEOIP_DATABASE_PATH}", exc_info=True)
            _geoip_reader = None
        except Exception as e:
            logger.error(f"Failed to initialize GeoIP reader with an unexpected error: {e}", exc_info=True)
            _geoip_reader = None

def get_country_from_ip(ip_address: str) -> Optional[str]:
    global _geoip_reader # Ensure we're using the global reader

    if _geoip_reader is None:
        _initialize_geoip_reader() # Attempt to initialize on first call
        if _geoip_reader is None: # If still None after attempt, it failed
            # Warning already logged by _initialize_geoip_reader if it fails
            return None

    if not ip_address: # Basic validation
        return None

    try:
        response = _geoip_reader.country(ip_address)
        return response.country.name
    except geoip2.errors.AddressNotFoundError:
        # This is common for private IPs or IPs not in the database, so debug level might be more appropriate.
        # logger.debug(f"IP address {ip_address} not found in GeoIP database.")
        return None
    except Exception as e:
        # Log other unexpected errors during lookup.
        logger.error(f"Error during GeoIP lookup for {ip_address}: {e}", exc_info=False) # exc_info can be noisy for many lookups
        return None

# Optional: Eager initialization at module load time.
# _initialize_geoip_reader()
# Current implementation uses lazy initialization on the first call to get_country_from_ip.
# This is generally preferred for faster application startup, especially if GeoIP is not always needed.
# If GeoIP is critical and any startup delay is acceptable, uncommenting the line above would initialize it once.
# For now, lazy initialization is kept.