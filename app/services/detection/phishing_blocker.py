# External Libraries:
# - aiohttp: For asynchronous HTTP requests (fetching HTML content).
# - tldextract: For accurate domain component extraction. (Used by ClassicalPhishingDetector)
# - dnspython: For DNS record lookups. (Used by ClassicalPhishingDetector)
# - python-whois: For fetching WHOIS domain registration data. (Used by ClassicalPhishingDetector)
# - python-Levenshtein: For calculating domain similarity. (Used by ClassicalPhishingDetector)

import json
import os
import aiohttp # For asynchronous HTTP requests
import asyncio
from typing import Dict, List, Set, Optional
import multiprocessing # Used by ClassicalPhishingDetector
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
import tldextract # Used by ClassicalPhishingDetector
import re 
import logging
from socketio import Client # For Socket.IO communication
from .phishing_detector import ClassicalPhishingDetector, PhishingResult 


logger = logging.getLogger(__name__)
# Define a constant for the data directory path for clarity and ease of modification.
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class PhishingBlocker:
    """
    Manages phishing detection and blocking logic for network traffic.

    This class integrates with `ClassicalPhishingDetector` for detailed URL and HTML content
    analysis. It is designed to process HTTP activity data, typically provided by a
    packet sniffer. Key responsibilities include:
    - Asynchronously fetching HTML content for URLs to aid detection.
    - Managing user-defined and external whitelists/blacklists, persisted to files.
    - Communicating detection results, alerts, and operational statistics via Socket.IO.
    - Handling real-time policy updates (whitelist/blacklist changes) from users.
    - Providing an interface for manual, on-demand URL checks.

    The PhishingBlocker operates primarily in an asynchronous manner using `asyncio` for
    I/O-bound tasks like HTTP requests and Socket.IO communication. The underlying
    `ClassicalPhishingDetector` may use multiprocessing for its CPU-bound analysis tasks.

    Integration with Packet Sniffer:
    The `PacketSniffer` component calls the `submit_http_for_analysis` method of this class.
    This submission is non-blocking; `submit_http_for_analysis` schedules the actual
    processing (`process_http_activity`) to run as an asynchronous background task.

    Key Limitations:
    - HTTPS Content Inspection: Does not perform TLS interception; analysis relies on
      URL/domain features, DNS/WHOIS data, and unencrypted portions of traffic or
      explicitly fetched HTML content (primarily for HTTP URLs or initial redirects).
    - Dynamic Content: Full JavaScript execution for analyzing dynamically rendered
      content is not implemented. Analysis of fetched HTML is based on its static state.
    - Email Analysis: Placeholder methods for email header, body, and attachment
      scanning exist in `ClassicalPhishingDetector` but require significant further
      development with specialized libraries or services to be functional.
    - Machine Learning: ML model integration is a placeholder in `ClassicalPhishingDetector`.
      A trained model and a feature extraction/inference pipeline are needed.
    - Blocking Mechanism: Blocking is primarily application-level (e.g., by maintaining
      a list of blocked domains for other components to use). It does not directly
      implement OS-level firewall rule integration.
    - External Data Reliability: WHOIS data fetching can be unreliable due to rate limits,
      varying registrar responses, and TLDs not supporting public WHOIS. DNS lookups
      are subject to network conditions and DNS server reliability.
    - Resource Management: Fetching content for every URL can be resource-intensive.
      Heuristics are used to limit fetches to likely HTML pages, but this may need tuning.
    """
    def __init__(self, sio: Client):
        """
        Initializes the PhishingBlocker.

        Args:
            sio (socketio.Client): An initialized Socket.IO client instance for
                                   real-time communication with the frontend/clients.
        """
        self.sio = sio
        self.detector = ClassicalPhishingDetector() 
        self.http_session: Optional[aiohttp.ClientSession] = None # Initialized when first needed via _initialize_http_session
        self.running = multiprocessing.Value("b", True) # Controls background asyncio tasks

        # Blocking sets - primarily for application-level blocking decisions based on detection.
        self.blocked_domains: Set[str] = set() # Domains actively blocked by this PhishingBlocker instance.
        self.blocked_ips: Set[str] = set()     # IPs associated with blocked domains (currently not heavily used but available).

        # Define file paths for persistent storage of whitelists and blacklists.
        self._ensure_data_dir_exists() # Create data directory if it doesn't exist.
        self.user_whitelist_file = os.path.join(DATA_DIR, "user_whitelist.txt")
        self.user_blacklist_file = os.path.join(DATA_DIR, "user_blacklist.txt")
        # Example: can be expanded to load multiple external blacklist files from a config.
        self.external_blacklist_files = [os.path.join(DATA_DIR, "external_blacklist_1.txt")] 

        # Load whitelists/blacklists from files into memory.
        # This populates the detector's internal sets and PhishingBlocker's active block list.
        self._load_persistent_lists() 
        self.load_external_blacklists(self.external_blacklist_files) 

        # Statistics counters for periodic reporting via Socket.IO.
        self.urls_scanned_since_last_update: int = 0
        self.phishing_detected_since_last_update: int = 0
        self.last_stats_update_time: float = time.monotonic() # Using monotonic clock for reliable interval measurement.
        self.stats_update_interval: int = 3600  # Default: 1 hour in seconds (can be made configurable).
        self.stats_update_task: Optional[asyncio.Task] = None # Stores the asyncio task for periodic stats updates.

        # Start the ClassicalPhishingDetector's internal processes (e.g., its multiprocessing pool).
        self.detector.start() 

        # Initialize and start PhishingBlocker's own background asyncio tasks.
        # Task for processing results from the detector's internal queue.
        self.result_processor_task: asyncio.Task = asyncio.create_task(self.process_detection_results())
        # Task for periodically emitting phishing detection statistics.
        self.stats_update_task: asyncio.Task = asyncio.create_task(self.schedule_phishing_stats_update())

        # Register Socket.IO event handlers for real-time communication and control.
        self.register_socket_handlers()
        
        logger.info("PhishingBlocker initialized and background tasks started.")


    async def _initialize_http_session(self):
        """
        Initializes or re-initializes the `aiohttp.ClientSession` if it's None or closed.
        This method is called before making HTTP requests to ensure the session is active and ready.
        Configures default timeouts for the session.
        """
        if self.http_session is None or self.http_session.closed:
            # Configure client timeouts: 5 seconds for connect, 10 seconds total for the request.
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            self.http_session = aiohttp.ClientSession(timeout=timeout)
            # PROD_CLEANUP: logger.debug("aiohttp.ClientSession initialized or re-initialized.")


    def _ensure_data_dir_exists(self):
        """
        Ensures that the data directory (defined by `DATA_DIR`) for storing whitelists,
        blacklists, and other persistent data exists. If not, it attempts to create
        the directory and any configured placeholder list files.
        """
        if not os.path.exists(DATA_DIR):
            try:
                os.makedirs(DATA_DIR)
                logger.info(f"Created data directory: {DATA_DIR}")
                # Create empty placeholder files for user lists and configured external lists
                # This simplifies initial setup and ensures file operations don't fail later.
                files_to_ensure = [self.user_whitelist_file, self.user_blacklist_file] + self.external_blacklist_files
                for f_path in files_to_ensure:
                    if not os.path.exists(f_path): # Check again before creating each file
                        try:
                            with open(f_path, 'w', encoding='utf-8') as f: # Create empty file with UTF-8 encoding
                                pass 
                            logger.info(f"Created empty placeholder file: {f_path}")
                        except IOError as e_file:
                            logger.error(f"Error creating placeholder file {f_path}: {e_file}", exc_info=True)
            except OSError as e_dir: # Catch potential errors during directory creation
                logger.error(f"Error creating data directory {DATA_DIR}: {e_dir}", exc_info=True)


    def _load_persistent_lists(self):
        """
        Loads user-defined whitelists and blacklists from their respective files.
        This method updates the `ClassicalPhishingDetector`'s internal `trusted_domains`
        and `blacklisted_domains` sets, and also populates the `PhishingBlocker`'s
        own `blocked_domains` set with items from the user blacklist for active blocking.
        """
        user_wl = self._load_from_file(self.user_whitelist_file)
        self.detector.trusted_domains.update(user_wl) 
        logger.info(f"Loaded {len(user_wl)} domains from user whitelist '{self.user_whitelist_file}' into detector.")

        user_bl = self._load_from_file(self.user_blacklist_file)
        self.detector.blacklisted_domains.update(user_bl) 
        self.blocked_domains.update(user_bl) # Add user-blacklisted domains to PhishingBlocker's active block list.
        logger.info(f"Loaded {len(user_bl)} domains from user blacklist '{self.user_blacklist_file}' into detector and blocker.")


    def _load_from_file(self, file_path: str) -> Set[str]:
        """
        Helper method to load a set of domains or URLs from a specified text file.
        Each line in the file is treated as an item. Lines starting with '#' (comments)
        and empty lines are ignored. All items are converted to lowercase for consistency.

        Args:
            file_path (str): The path to the file to load items from.

        Returns:
            Set[str]: A set of string items loaded from the file. Returns an empty set
                      if the file doesn't exist or an error occurs during reading.
        """
        items: Set[str] = set()
        try:
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f: # Specify UTF-8 encoding for broader compatibility.
                    for line_number, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith("#"): # Ignore comments and empty lines.
                            items.add(line.lower()) # Normalize to lowercase.
            else:
                # If a list file doesn't exist, it might be the first run or a configuration issue.
                logger.info(f"File not found: {file_path}. Returning empty set. Will be created if items are saved to it.")
        except IOError as e: # Catch file I/O specific errors.
            logger.error(f"IOError loading items from file {file_path}: {e}", exc_info=True)
        except Exception as e: # Catch any other unexpected errors during file processing.
            logger.error(f"Unexpected error loading file {file_path}: {e}", exc_info=True)
        return items


    def _save_to_file(self, file_path: str, data_set: Set[str]):
        """
        Helper method to save a set of domains or URLs to a specified text file,
        with one item per line. Items are saved in sorted order to ensure consistency
        and make diffs easier if the files are version controlled.

        Args:
            file_path (str): The path to the file where the data should be saved.
            data_set (Set[str]): A set of string items to save to the file.
        """
        try:
            # Ensure the directory exists before trying to write the file.
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f: # Specify UTF-8 encoding.
                for item in sorted(list(data_set)): # Save in sorted order for consistency.
                    f.write(f"{item}\n")
            # PROD_CLEANUP: logger.debug(f"Successfully saved {len(data_set)} items to {file_path}")
        except IOError as e: # Catch file I/O specific errors.
            logger.error(f"IOError saving items to file {file_path}: {e}", exc_info=True)
        except Exception as e: # Catch any other unexpected errors during file writing.
            logger.error(f"Unexpected error saving to file {file_path}: {e}", exc_info=True)


    def load_external_blacklists(self, file_paths: List[str]):
        """
        Loads domains/URLs from one or more external blacklist files into the
        `ClassicalPhishingDetector`'s `blacklisted_domains` set.

        Args:
            file_paths (List[str]): A list of file paths for the external blacklist files.
                                    Each file should contain one domain/URL per line.
        """
        total_loaded_count = 0
        for file_path in file_paths:
            external_bl_items = self._load_from_file(file_path)
            if external_bl_items:
                self.detector.blacklisted_domains.update(external_bl_items)
                total_loaded_count += len(external_bl_items)
                logger.info(f"Loaded {len(external_bl_items)} items from external blacklist: {file_path}")
        if total_loaded_count > 0:
            logger.info(f"Total {total_loaded_count} items loaded from {len(file_paths)} external blacklist file(s). Detector blacklist size now: {len(self.detector.blacklisted_domains)}")


    async def schedule_phishing_stats_update(self):
        """
        Periodically calls the `phishing_stats_update` method based on the configured
        `self.stats_update_interval`. This method runs as a background asyncio task.
        It continues to run as long as `self.running.value` is True.
        """
        logger.info(f"Phishing statistics update scheduler started. Update interval: {self.stats_update_interval} seconds.")
        while self.running.value: # Loop continues as long as the blocker service is running.
            try:
                await self.phishing_stats_update() # Call the stats update method.
                await asyncio.sleep(self.stats_update_interval) # Wait for the next interval.
            except asyncio.CancelledError:
                logger.info("Phishing stats update task was cancelled.")
                break # Exit the loop if the task is cancelled.
            except Exception as e: # Catch any other unexpected errors in the scheduling loop.
                logger.error(f"Error in schedule_phishing_stats_update loop: {e}", exc_info=True)
                # Avoid rapid looping on persistent errors; wait for a fraction of the interval or a fixed short time.
                await asyncio.sleep(self.stats_update_interval / 10 if self.stats_update_interval > 100 else 10)


    async def phishing_stats_update(self):
        """
        Compiles various phishing detection statistics and emits them over Socket.IO
        using the "phishing_stats_update" event. Resets per-interval counters after emission.
        """
        current_time = time.monotonic()
        time_elapsed = current_time - self.last_stats_update_time

        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "phishing_stats", # Standardized field for SIEM systems and client-side event routing.
            "period_seconds": round(time_elapsed, 2),
            "urls_scanned_in_period": self.urls_scanned_since_last_update,
            "phishing_detected_in_period": self.phishing_detected_since_last_update,
            "total_trusted_domains": len(self.detector.trusted_domains), # Size of the detector's trusted domain set.
            "total_blacklisted_domains_detector": len(self.detector.blacklisted_domains), # Size of detector's blacklist.
            "total_blocked_domains_blocker": len(self.blocked_domains), # Size of PhishingBlocker's active block list.
        }
        try:
            await self.sio.emit("phishing_stats_update", stats)
            # PROD_CLEANUP: logger.debug(f"Emitted phishing statistics: {stats}")
            # Reset counters for the next reporting interval.
            self.urls_scanned_since_last_update = 0
            self.phishing_detected_since_last_update = 0
            self.last_stats_update_time = current_time
        except Exception as e: # Catch errors related to Socket.IO emission (e.g., connection issues).
            logger.error(f"Error emitting phishing statistics via Socket.IO: {e}", exc_info=True)


    def register_socket_handlers(self):
        """
        Registers Socket.IO event handlers for real-time interactions such as manual URL checks,
        whitelist/blacklist management, and requests for current status information.
        These handlers allow clients (e.g., a web UI) to interact with the PhishingBlocker.
        """
        logger.info("Registering PhishingBlocker Socket.IO event handlers.")

        @self.sio.on("manual_phishing_check")
        async def handle_manual_check(data: Dict):
            """
            Handles a "manual_phishing_check" Socket.IO event from a client.
            Analyzes the provided URL (optionally fetching its HTML content if it seems appropriate)
            and emits a "phishing_check_result" event back to the client with the analysis outcome.
            If phishing is detected and confirmed through this manual check, the domain is
            added to the user blacklist and the PhishingBlocker's active block list.

            Args:
                data (Dict): Data received with the event. Expected to contain "url" (str),
                             the URL to be checked.
            """
            await self._initialize_http_session() # Ensure aiohttp session is ready for potential HTML fetch.
            url_to_check = data.get("url")
            if not url_to_check or not isinstance(url_to_check, str) or not url_to_check.strip():
                logger.warning("Manual phishing check requested with invalid or missing URL.")
                await self.sio.emit("phishing_check_result", {"error": "URL missing or invalid."})
                return

            url_to_check = url_to_check.strip()
            # PROD_CLEANUP: logger.info(f"Received manual_phishing_check event for URL: {url_to_check}")

            # The internal `manual_check` method handles the analysis and returns a result dictionary.
            result_dict = await self.manual_check(url_to_check) 
            
            await self.sio.emit("phishing_check_result", result_dict)


        @self.sio.on("get_blocked_domains") 
        async def handle_get_blocked(data: Optional[Dict] = None): # data param for future use, e.g., pagination or filtering.
            """
            Handles a "get_blocked_domains" Socket.IO event.
            Emits a "blocked_domains_list" event containing the current sets of
            domains and IPs actively blocked by the PhishingBlocker.
            This can be used by clients to display the current block status.

            Args:
                data (Optional[Dict]): Optional data from the client (currently unused).
            """
            # PROD_CLEANUP: logger.debug("Received get_blocked_domains request via Socket.IO.")
            await self.sio.emit(
                "blocked_domains_list",
                {"domains": list(self.blocked_domains), "ips": list(self.blocked_ips)},
            )

        # --- Whitelist/Blacklist Management Socket.IO Handlers ---
        @self.sio.on("add_to_whitelist")
        async def handle_add_to_whitelist(data: Dict):
            """
            Handles "add_to_whitelist" Socket.IO event. Adds a domain to the user whitelist,
            updates the detector's trusted domains set, removes it from any active blocklists
            (both in PhishingBlocker and the detector's blacklist), persists changes to the
            user_whitelist.txt file, and emits a confirmation event.

            Args:
                data (Dict): Expected to contain "domain" (str) to be whitelisted.
            """
            domain_to_whitelist = data.get("domain", "").lower().strip() # Normalize: lowercase and strip whitespace.
            if not domain_to_whitelist: 
                # PROD_CLEANUP: logger.debug("Add to whitelist request received with an empty domain.")
                await self.sio.emit("whitelist_updated", {"action": "add_failed", "error": "Domain cannot be empty."})
                return
            
            self.detector.trusted_domains.add(domain_to_whitelist)
            
            # Ensure consistency: if whitelisting, remove from active block lists and detector's blacklist.
            if domain_to_whitelist in self.blocked_domains:
                self.blocked_domains.remove(domain_to_whitelist)
                logger.info(f"Removed '{domain_to_whitelist}' from PhishingBlocker's active block list due to whitelisting.")
            if domain_to_whitelist in self.detector.blacklisted_domains:
                self.detector.blacklisted_domains.remove(domain_to_whitelist)
                logger.info(f"Removed '{domain_to_whitelist}' from ClassicalPhishingDetector's internal blacklist due to whitelisting.")

            self._save_to_file(self.user_whitelist_file, self.detector.trusted_domains)
            
            # Also ensure it's removed from the user_blacklist.txt file for complete consistency.
            user_bl_set = self._load_from_file(self.user_blacklist_file)
            if domain_to_whitelist in user_bl_set:
                user_bl_set.remove(domain_to_whitelist)
                self._save_to_file(self.user_blacklist_file, user_bl_set)
                logger.info(f"Removed '{domain_to_whitelist}' from user_blacklist.txt file due to whitelisting.")

            logger.info(f"Added '{domain_to_whitelist}' to user whitelist. Total trusted domains: {len(self.detector.trusted_domains)}")
            await self.sio.emit("whitelist_updated", {"action": "added", "domain": domain_to_whitelist, "count": len(self.detector.trusted_domains)})


        @self.sio.on("remove_from_whitelist")
        async def handle_remove_from_whitelist(data: Dict):
            """
            Handles "remove_from_whitelist" Socket.IO event. Removes a domain from the
            user whitelist, updates the detector's trusted domains, persists changes,
            and emits a confirmation.

            Args:
                data (Dict): Expected to contain "domain" (str) to be removed from the whitelist.
            """
            domain_to_remove = data.get("domain", "").lower().strip()
            if not domain_to_remove: 
                # PROD_CLEANUP: logger.debug("Remove from whitelist request received with an empty domain.")
                await self.sio.emit("whitelist_updated", {"action": "remove_failed", "error": "Domain cannot be empty."})
                return
            
            if domain_to_remove in self.detector.trusted_domains:
                self.detector.trusted_domains.remove(domain_to_remove)
                self._save_to_file(self.user_whitelist_file, self.detector.trusted_domains)
                logger.info(f"Removed '{domain_to_remove}' from user whitelist. Total trusted domains: {len(self.detector.trusted_domains)}")
                await self.sio.emit("whitelist_updated", {"action": "removed", "domain": domain_to_remove, "count": len(self.detector.trusted_domains)})
            else:
                logger.info(f"Domain '{domain_to_remove}' not found in user whitelist for removal.")
                await self.sio.emit("whitelist_updated", {"action": "remove_failed", "error": "Domain not found in whitelist." , "domain": domain_to_remove})


        @self.sio.on("add_to_blacklist")
        async def handle_add_to_blacklist(data: Dict):
            """
            Handles "add_to_blacklist" Socket.IO event. Adds a domain to the user blacklist,
            updates detector's and blocker's internal blacklists, persists to file, removes
            from whitelist if present, and emits confirmation.

            Args:
                data (Dict): Expected to contain "domain" (str) to be blacklisted.
            """
            domain_to_blacklist = data.get("domain", "").lower().strip()
            if not domain_to_blacklist: 
                # PROD_CLEANUP: logger.debug("Add to blacklist request received with an empty domain.")
                await self.sio.emit("blacklist_updated", {"action": "add_failed", "error": "Domain cannot be empty."})
                return

            self.detector.blacklisted_domains.add(domain_to_blacklist)
            self.blocked_domains.add(domain_to_blacklist) # Add to PhishingBlocker's active block list immediately.
            self._save_to_file(self.user_blacklist_file, self.detector.blacklisted_domains)
            
            # Ensure consistency: remove from whitelist if it's being blacklisted.
            if domain_to_blacklist in self.detector.trusted_domains:
                self.detector.trusted_domains.remove(domain_to_blacklist)
                self._save_to_file(self.user_whitelist_file, self.detector.trusted_domains)
                logger.info(f"Removed '{domain_to_blacklist}' from user whitelist as it was added to blacklist.")

            logger.info(f"Added '{domain_to_blacklist}' to user blacklist. Total detector blacklisted: {len(self.detector.blacklisted_domains)}")
            await self.sio.emit("blacklist_updated", {"action": "added", "domain": domain_to_blacklist, "count": len(self.detector.blacklisted_domains)})


        @self.sio.on("remove_from_blacklist")
        async def handle_remove_from_blacklist(data: Dict):
            """
            Handles "remove_from_blacklist" Socket.IO event. Removes a domain from the
            user blacklist, updates relevant internal sets, persists changes, and emits confirmation.

            Args:
                data (Dict): Expected to contain "domain" (str) to be removed from the blacklist.
            """
            domain_to_remove = data.get("domain", "").lower().strip()
            if not domain_to_remove: 
                # PROD_CLEANUP: logger.debug("Remove from blacklist request received with an empty domain.")
                await self.sio.emit("blacklist_updated", {"action": "remove_failed", "error": "Domain cannot be empty."})
                return
            
            removed_from_detector = False
            if domain_to_remove in self.detector.blacklisted_domains:
                self.detector.blacklisted_domains.remove(domain_to_remove)
                removed_from_detector = True
            
            removed_from_blocker = False
            if domain_to_remove in self.blocked_domains: # Also remove from PhishingBlocker's active block list.
                self.blocked_domains.remove(domain_to_remove)
                removed_from_blocker = True
            
            if removed_from_detector or removed_from_blocker:
                # Persist changes to the user_blacklist.txt file. This file reflects the user-added items
                # that should be in the detector's blacklist.
                user_bl_set = self._load_from_file(self.user_blacklist_file) # Load current state of file
                if domain_to_remove in user_bl_set: # Ensure it's removed from the set that gets saved
                    user_bl_set.remove(domain_to_remove)
                self._save_to_file(self.user_blacklist_file, user_bl_set) 
                
                logger.info(f"Removed '{domain_to_remove}' from user blacklist (Detector: {removed_from_detector}, Blocker: {removed_from_blocker}). Total detector blacklisted: {len(self.detector.blacklisted_domains)}")
                await self.sio.emit("blacklist_updated", {"action": "removed", "domain": domain_to_remove, "count": len(self.detector.blacklisted_domains)})
            else:
                logger.info(f"Domain '{domain_to_remove}' not found in user blacklist for removal.")
                await self.sio.emit("blacklist_updated", {"action": "remove_failed", "error": "Domain not found in blacklist.", "domain": domain_to_remove})


        @self.sio.on("refresh_external_blacklists")
        async def handle_refresh_external_blacklists(data: Optional[Dict] = None): 
            """
            Handles "refresh_external_blacklists" Socket.IO event. Reloads domains from configured
            external blacklist files into the `ClassicalPhishingDetector`'s blacklist.
            This allows updating threat intelligence without restarting the application.

            Args:
                data (Optional[Dict]): Optional data from client (currently unused).
            """
            logger.info("Refreshing external blacklists triggered via Socket.IO.")
            # Note: Current implementation of load_external_blacklists adds to the existing set.
            # For a true "refresh" that removes old entries from a specific external list before reloading,
            # a more complex mechanism would be needed to track origins of blacklist entries.
            # For now, it effectively re-adds/updates items from the configured files.
            self.load_external_blacklists(self.external_blacklist_files) # Reloads from files defined in self.external_blacklist_files
            logger.info(f"External blacklists refreshed. Total detector blacklist size now: {len(self.detector.blacklisted_domains)}")
            await self.sio.emit("external_blacklists_refreshed", {"status": "success", "total_detector_blacklist": len(self.detector.blacklisted_domains)})


        @self.sio.on("report_suspected_phishing")
        async def handle_report_suspected_phishing(data: Dict):
            """
            Handles "report_suspected_phishing" Socket.IO event from a user.
            Logs the reported URL and any comments. Emits an "admin_notification" event
            for potential review by administrators and acknowledges receipt to the user.

            Args:
                data (Dict): Expected to contain "url" (str), and optionally "comment" (str)
                             and "source_ip" (str) of the reporter.
            """
            reported_url = data.get("url", "").strip()
            user_comment = data.get("comment", "") 
            user_ip = data.get("source_ip", "N/A") # IP of the reporting user, if available from client (e.g., X-Forwarded-For)

            if not reported_url:
                logger.warning("Received empty URL in suspected phishing report.")
                await self.sio.emit("report_phishing_result", {"status": "error", "message": "URL missing in report."})
                return

            # Log the user's report. This is important for tracking and potential manual review.
            logger.warning(f"PHISHING REPORTED by user (IP: {user_ip}): URL='{reported_url}', Comment='{user_comment}'. Further review may be needed.")
            
            # Future enhancements:
            # - Could trigger an immediate high-priority scan of the reported URL.
            # - Could add the URL to a "pending review" queue in a database or admin interface.
            
            # Emit a notification specifically for an admin interface or logging system.
            admin_alert_data = {
                "event_type": "user_phishing_report", # For SIEM/client-side routing.
                "reported_url": reported_url,
                "user_comment": user_comment,
                "reporter_ip": user_ip, # Be mindful of privacy regulations (e.g., GDPR) if logging/storing user IPs.
                "timestamp": datetime.utcnow().isoformat(),
                "status": "received_for_review" # Indicates the report is logged for manual/automated review.
            }
            await self.sio.emit("admin_notification", admin_alert_data) 
            
            # Acknowledge receipt to the reporting user.
            await self.sio.emit("report_phishing_result", {"status": "success", "message": "Report received. Thank you for helping improve security."})


    async def send_alert(self, result: PhishingResult, action_taken: str = "potential_phishing_detected", source_ip: Optional[str] = None):
        """
        Sends a structured phishing alert over Socket.IO to all connected clients.
        The alert includes details from the `PhishingResult` object, the action taken,
        and optionally the source IP of the request that triggered the detection.
        It also adds a severity level and a flag for credential theft risk if applicable.

        Args:
            result (PhishingResult): The analysis result object from `ClassicalPhishingDetector`.
            action_taken (str): Describes the action taken (e.g., "blocked_by_live_detection",
                                "suspicious_activity_detected").
            source_ip (Optional[str]): The source IP associated with the activity, if available.
        """
        alert_data = {
            "event_type": "phishing_alert", # Standardized field for SIEM systems and client-side event routing.
            "url": result.url,
            "risk_score": result.risk_score,
            "reasons": result.reasons,
            "is_phishing": result.is_phishing, # True if classified as phishing, False otherwise.
            "action_taken": action_taken, 
            "timestamp": result.timestamp, # Use timestamp from PhishingResult for consistency.
        }
        if source_ip: # Add source IP if available from the context (e.g., HTTP activity).
            alert_data["source_ip"] = source_ip

        # Highlight credential theft risk based on specific detector reasons.
        # These specific reason strings should match those produced by ClassicalPhishingDetector.analyze_html_content.
        if any("html_password_form_foreign_domain" in reason for reason in result.reasons) or \
           any("Password form submits to a different domain" in reason for reason in result.reasons):
            alert_data["credential_theft_risk"] = True
            alert_data["severity"] = "HIGH" # Add severity field for easier filtering/prioritization.
        elif result.is_phishing:
            alert_data["severity"] = "MEDIUM" # Default for other confirmed phishing detections.
        else:
            # For non-phishing but potentially suspicious alerts (if this method is used for such cases).
            alert_data["severity"] = "LOW"
        
        # Refine payload for PhishingDetectionsTable.tsx (Task 6)
        unique_id_ts = result.timestamp.replace(':', '-').replace('.', '-') # Ensure timestamp is filesystem-friendly if used in IDs
        refined_alert_data = {
            "id": f"phish_{unique_id_ts}_{result.url[:50]}", # Unique ID
            "timestamp": result.timestamp, # Already ISO format from PhishingResult
            "url": result.url,
            "source_ip": source_ip, # Client IP that accessed/was served the URL
            "confidence": result.risk_score, # Detection confidence (0-1 scale)
            "status": "Blocked" if "blocked" in action_taken.lower() else "Detected",
            "threat_type": "Phishing", # Fixed type for this event
            "severity": alert_data["severity"], # Determined above
            "reasons": result.reasons,
            # "is_phishing": result.is_phishing, # This is implicit in the event name / severity
            # "credential_theft_risk": alert_data.get("credential_theft_risk", False) # Optional, can be in metadata if needed
        }

        try:
            await self.sio.emit("phishing_link_detected", refined_alert_data) # Changed event name
            logger.info(f"Sent phishing_link_detected event for URL '{result.url}', Risk: {result.risk_score}, Action: {action_taken}, Reasons: {'; '.join(result.reasons)}")
        except Exception as e:
            logger.error(f"Error emitting phishing_link_detected via Socket.IO for URL '{result.url}': {e}", exc_info=True)


    async def send_block_notification(self, domain: str, ip: Optional[str] = None, url: Optional[str] = None, reasons: Optional[List[str]] = None):
        """
        Notifies connected clients via Socket.IO about a resource (domain/IP) that has been blocked.
        The notification includes the blocked domain, associated IP (if any), the specific URL
        that triggered the block (if applicable), and reasons for the block.

        Args:
            domain (str): The domain that was blocked.
            ip (Optional[str]): The IP address associated with the blocked domain, if available.
            url (Optional[str]): The specific URL that triggered the block, if applicable.
            reasons (Optional[List[str]]): A list of reasons why the resource was blocked.
        """
        timestamp = datetime.utcnow().isoformat()
        event_data = {
            "event_type": "resource_blocked", # For SIEM systems and client-side event routing.
            "domain": domain,
            "ip_address": ip if ip else "N/A", # Associated IP if available, "N/A" otherwise.
            "url_blocked": url if url else f"http://{domain}/", # Provide specific URL if known, else fallback to domain.
            "reasons": reasons if reasons else ["Identified as phishing or malicious"], # Default reason if not specified.
            "timestamp": timestamp,
        }
        try:
            await self.sio.emit("resource_blocked", event_data)
            logger.info(f"Sent block notification for domain: '{domain}', IP: {ip or 'N/A'}, URL: {url or 'N/A'}, Reasons: {event_data['reasons']}")
        except Exception as e:
            logger.error(f"Error emitting resource_blocked notification via Socket.IO for domain '{domain}': {e}", exc_info=True)


    def submit_http_for_analysis(self, http_data: Dict):
        """
        Synchronous entry point, typically called by the `PacketSniffer`, to submit HTTP
        transaction data for phishing analysis. This method schedules the asynchronous
        `process_http_activity` method to run in the background using Socket.IO's
        async task manager (`sio.start_background_task`). This ensures that the caller
        (e.g., the sniffer's packet handling loop) is not blocked by potentially
        long-running operations like network requests for HTML content.

        Args:
            http_data (Dict): A dictionary containing HTTP transaction details.
                              Expected keys include 'host', 'path'. Optional keys include
                              'source_ip', and 'headers'.
        """
        try:
            # The aiohttp session will be initialized within the async process_http_activity method
            # when it's first needed, ensuring it's created within the correct asyncio event loop.
            self.sio.start_background_task(self.process_http_activity, http_data)
            # PROD_CLEANUP: logger.debug(f"Submitted HTTP data for host '{http_data.get('host', 'N/A')}' for asynchronous phishing analysis.")
        except Exception as e: # Catch potential errors if sio or its background task mechanism fails.
            logger.error(f"Error submitting HTTP data for asynchronous analysis: {e}", exc_info=True)


    async def process_http_activity(self, http_data: Dict):
        """
        Asynchronously processes HTTP activity data received (e.g., from a packet sniffer).
        This method performs several steps:
        1. Initializes an `aiohttp.ClientSession` if not already available.
        2. Checks if the requested domain/IP is already in the PhishingBlocker's active block list.
           If so, it sends a block notification and exits early.
        3. If not already blocked, it determines if fetching HTML content for the URL is appropriate
           (based on heuristics like file extensions or Content-Type headers if available).
        4. If HTML fetching is deemed appropriate, it asynchronously GETs the content.
        5. Calls the `ClassicalPhishingDetector`'s `analyze_url` method with the URL and
           any fetched HTML content.
        6. Based on the analysis result, it may add the domain to the block list, send phishing
           alerts, and/or send block notifications.
        7. Returns a dictionary indicating the action taken ("blocked" or "allowed") and analysis details.

        Args:
            http_data (Dict): Dictionary with HTTP transaction details. Expected keys:
                              'host' (str): The target host (domain or IP).
                              'path' (str): The request path (e.g., "/login.php").
                              'source_ip' (str, optional): Source IP of the client making the request.
                              'headers' (Dict, optional): HTTP request/response headers, which might include
                                                          'Content-Type' to guide HTML fetching decisions.

        Returns:
            Optional[Dict]: A dictionary indicating the action taken (e.g., {"action": "blocked", ...})
                            or None if processing could not proceed (e.g., host missing in input).
        """
        await self._initialize_http_session() # Ensure aiohttp session is ready for this task.

        host = http_data.get("host")
        path = http_data.get("path", "/") # Default to root path if not provided.
        source_ip = http_data.get("source_ip", "N/A") 

        if not host:
            # PROD_CLEANUP: logger.debug("process_http_activity: Host missing in http_data. Cannot analyze.")
            return None 

        # Normalize URL scheme. The detector also normalizes, but being consistent here is good.
        url = f"http://{host}{path}" # Start with http; detector will handle if it's already https or needs normalization.
        if "://" in host: # If host already includes a scheme (e.g., from absoluteURI in HTTP/1.1 proxy requests).
            url = f"{host}{path}"


        # 1. Early exit: Check if domain or source IP is already explicitly blocked by PhishingBlocker's lists.
        # This uses urlparse().hostname to correctly extract the hostname from URLs that might include ports.
        domain_to_check = urlparse(url).hostname 
        if not domain_to_check: domain_to_check = host # Fallback if urlparse fails to get a hostname (e.g. for raw IPs).

        if domain_to_check in self.blocked_domains or \
           (source_ip != "N/A" and source_ip in self.blocked_ips):
            logger.info(f"Access to already blocked resource: Domain='{domain_to_check}', IP='{source_ip}' for URL='{url}'")
            await self.send_block_notification(domain=domain_to_check, ip=source_ip, url=url, reasons=["Previously blocked by PhishingBlocker"])
            # The caller (e.g., a firewall module) would use this return value to decide the actual blocking action.
            return {"action": "blocked", "reason": "previously_blocked_by_blocker", "url": url}


        # 2. Fetch HTML content if applicable (e.g., for text/html responses).
        html_content: Optional[str] = None
        # Heuristic to decide if fetching HTML is worthwhile.
        # Check common HTML file extensions, root paths, or explicit text/html content type from headers.
        content_type_header = http_data.get("headers", {}).get("Content-Type", "").lower()
        is_likely_html_page = any(url.endswith(ext) for ext in ['.html', '.htm', '.php', '.asp', '.aspx', '/']) or \
                              not tldextract.extract(url).suffix or \
                              "text/html" in content_type_header

        # Avoid fetching for known non-HTML content types if this information is available from headers.
        # This list can be expanded based on common non-HTML types observed.
        known_non_html_types = ['image/', 'video/', 'audio/', 'application/javascript', 
                                'text/css', 'application/json', 'application/xml', 
                                'application/pdf', 'application/octet-stream']
        if any(non_html_type in content_type_header for non_html_type in known_non_html_types):
            is_likely_html_page = False
            # PROD_CLEANUP: logger.debug(f"Skipping HTML fetch for URL '{url[:100]}' due to explicit non-HTML Content-Type: {content_type_header}")

        if is_likely_html_page and self.http_session: # Proceed only if it seems like an HTML page and session is available.
            try:
                # Use a reasonable timeout for the external HTTP GET request.
                async with self.http_session.get(url, timeout=aiohttp.ClientTimeout(total=7)) as response:
                    # Only process if successful and content type indicates HTML.
                    if response.status == 200 and \
                       ("text/html" in response.headers.get("Content-Type", "").lower()):
                        html_content = await response.text(encoding='utf-8', errors='ignore') # Specify encoding and handle potential errors.
                        # PROD_CLEANUP: logger.info(f"Fetched HTML content for URL '{url[:100]}' ({len(html_content)} bytes)")
                    else:
                        pass
                        # PROD_CLEANUP: logger.debug(f"Did not fetch HTML for URL '{url[:100]}'. Status: {response.status}, Content-Type: {response.headers.get('Content-Type')}")
            except asyncio.TimeoutError: # Specifically catch timeout errors.
                logger.warning(f"Timeout fetching HTML content for URL '{url[:100]}'")
            except aiohttp.ClientError as e: # Catch other aiohttp client-side errors (DNS resolution, connection errors, etc.).
                logger.warning(f"ClientError fetching HTML for URL '{url[:100]}': {type(e).__name__} - {e}")
            except Exception as e: # Catch any other unexpected errors during the fetch operation.
                logger.error(f"Unexpected error fetching HTML for URL '{url[:100]}': {e}", exc_info=True)

        # 3. Analyze URL (and HTML content if fetched) using the ClassicalPhishingDetector.
        # The detector's analyze_url method is synchronous internally for its rule processing.
        # However, its DNS and WHOIS lookups are blocking I/O operations. If these become a significant
        # bottleneck for the asyncio event loop, consider running this call in an executor:
        #   loop = asyncio.get_running_loop()
        #   result = await loop.run_in_executor(None, self.detector.analyze_url, url, html_content)
        # For now, a direct call is made, assuming the detector's internal I/O handling is acceptable or optimized.
        result: PhishingResult = self.detector.analyze_url(url, html_content=html_content)
        self.urls_scanned_since_last_update += 1 # Increment scan counter for statistics.


        # 4. Process detection result: block, alert, or log accordingly.
        if result.is_phishing:
            self.phishing_detected_since_last_update +=1
            domain_to_block = urlparse(result.url).hostname # Get hostname for blocking.
            if domain_to_block:
                self.blocked_domains.add(domain_to_block)
                # Future: Consider adding associated IP to self.blocked_ips if reliable and available.
                logger.info(f"LIVE DETECTION: Added '{domain_to_block}' to PhishingBlocker's active blocked_domains set. Total blocked: {len(self.blocked_domains)}")

            # Send alerts and notifications via Socket.IO.
            await self.send_alert(result, action_taken="blocked_by_live_detection", source_ip=source_ip)
            await self.send_block_notification(domain=domain_to_block, url=result.url, reasons=result.reasons, ip=source_ip)
            
            # Return action and details for the caller (e.g., PacketSniffer or other security components).
            return {"action": "blocked", "reason": "detected_phishing_live", "url": url, "details": result_dict_from_obj(result)}
        else:
            # Log if the URL is deemed suspicious but doesn't meet the full phishing threshold.
            if result.risk_score > 0.4: # This threshold for "suspicious" can be made configurable.
                 logger.info(f"Suspicious URL (not blocked): '{result.url}', Risk: {result.risk_score}, Reasons: {'; '.join(result.reasons)}")
                 # Optionally, send a different kind of alert for "suspicious but not blocked" activity if required.
            else:
                pass
                 # PROD_CLEANUP: logger.debug(f"Analyzed benign URL: '{result.url}', Risk: {result.risk_score}")

        return {"action": "allowed", "url": url, "details": result_dict_from_obj(result)}


    async def process_detection_results(self):
        """
        Background asyncio task to handle detection results coming from the
        `ClassicalPhishingDetector`'s internal result queue. This queue is typically
        populated when the detector's `live_monitor` method (which uses its
        multiprocessing pool via `pool.apply_async`) is invoked by another part of the system.

        If `process_http_activity` (called via `submit_http_for_analysis`) handles all
        analysis directly by calling `detector.analyze_url`, this queue might be less utilized
        unless other mechanisms also feed into the detector's pool.
        """
        logger.info("PhishingBlocker's 'process_detection_results' background task started.")
        while self.running.value: # Loop continues as long as the blocker service is active.
            try:
                if not self.detector.result_queue.empty():
                    # `ClassicalPhishingDetector.handle_result` puts a dictionary into its queue.
                    alert_dict_from_queue = self.detector.result_queue.get_nowait() # Non-blocking get.

                    url_from_queue = alert_dict_from_queue.get("url")
                    if not url_from_queue:
                        logger.warning("Received alert from detector's queue without a URL. Skipping.")
                        continue
                    
                    self.urls_scanned_since_last_update += 1 # Count items from the queue as scanned.

                    # Reconstruct a PhishingResult object or ensure data compatibility for send_alert.
                    # This reconstruction is based on the structure defined in ClassicalPhishingDetector.handle_result.
                    # A more robust system might involve serializing/deserializing PhishingResult objects directly.
                    result_for_alert = PhishingResult(
                        url=url_from_queue,
                        # Re-evaluate is_phishing based on score, as the queue item might just be raw data.
                        # Assuming a similar phishing threshold as used in analyze_url.
                        is_phishing=alert_dict_from_queue.get("risk_score", 0) >= self.detector.risk_weights.get("phishing_threshold", 0.7), 
                        risk_score=alert_dict_from_queue.get("risk_score", 0),
                        reasons=alert_dict_from_queue.get("reasons", []),
                        timestamp=alert_dict_from_queue.get("timestamp", datetime.utcnow().isoformat())
                    )

                    if result_for_alert.is_phishing: 
                        self.phishing_detected_since_last_update +=1
                        domain = urlparse(result_for_alert.url).hostname
                        action_taken_str = "blocked_from_detector_queue" # Action context.

                        if domain:
                            self.blocked_domains.add(domain)
                            logger.info(f"QUEUE DETECTION: Added '{domain}' to PhishingBlocker's active blocked_domains set. Total blocked: {len(self.blocked_domains)}")
                            # IP address is typically not available from this queue's context.
                            await self.send_block_notification(domain=domain, url=result_for_alert.url, reasons=result_for_alert.reasons)
                        
                        logger.warning(f"🚫 PHISHING DETECTED (from detector queue): URL='{result_for_alert.url}', Risk={result_for_alert.risk_score}, Reasons='{'; '.join(result_for_alert.reasons)}'. Action: {action_taken_str}")
                        await self.send_alert(result_for_alert, action_taken=action_taken_str)
                else:
                    await asyncio.sleep(0.1) # Check queue periodically without busy-waiting if it's empty.
            except multiprocessing.queues.Empty: # Should ideally not happen due to the queue.empty() check, but good for robustness.
                await asyncio.sleep(0.1) # Wait briefly before checking again.
            except Exception as e: # Catch any other unexpected errors in the loop.
                logger.error(f"Error in process_detection_results loop: {e}", exc_info=True)
                await asyncio.sleep(1) # Avoid rapid error loops on persistent errors by waiting longer.


    async def manual_check(self, url: str) -> Dict: 
        """
        Handles a manual phishing check request for a given URL, typically initiated by a user
        via a Socket.IO event or an API call. This method can optionally fetch HTML content
        for the URL to perform a more in-depth analysis.

        Args:
            url (str): The URL to be analyzed.

        Returns:
            Dict: A dictionary containing the phishing analysis result, structured similarly
                  to a `PhishingResult` object, including URL, phishing status, risk score,
                  reasons, and timestamp. It also includes a "blocked" field indicating if
                  the domain was added to the blocklist as a result of this manual check.
        """
        await self._initialize_http_session() # Ensure aiohttp session is ready for potential HTML fetch.
        # PROD_CLEANUP: logger.info(f"Initiating manual check for URL: {url}")
        self.urls_scanned_since_last_update += 1

        html_content_manual: Optional[str] = None
        if url.startswith(("http://", "https://")): # Only attempt to fetch content for valid HTTP/HTTPS schemes.
            try:
                async with self.http_session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200 and ("text/html" in response.headers.get("Content-Type", "").lower()):
                        html_content_manual = await response.text(encoding='utf-8', errors='ignore')
                        # PROD_CLEANUP: logger.info(f"Fetched HTML ({len(html_content_manual)} bytes) for manual check of URL: {url[:100]}")
                    else:
                        pass
                        # PROD_CLEANUP: logger.debug(f"HTML content not fetched for manual check (Status: {response.status}, Content-Type: {response.headers.get('Content-Type')}) for URL: {url}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout fetching HTML for manual check of URL: {url}")
            except aiohttp.ClientError as e: # Catch client-side HTTP errors.
                logger.warning(f"ClientError fetching HTML for manual check of URL: {url}: {e}")
            except Exception as e: # Catch any other unexpected errors during fetch.
                logger.error(f"Unexpected error fetching HTML for manual check of URL: {url}: {e}", exc_info=True)

        # Call the detector's analyze_url method with the URL and any fetched HTML content.
        result_obj: PhishingResult = self.detector.analyze_url(url, html_content=html_content_manual) 

        result_dict = result_dict_from_obj(result_obj) # Use helper for consistent dictionary structure.
        result_dict["event_type"] = "manual_check_result" # Add event_type for SIEM/logging consistency.

        # PROD_CLEANUP: logger.info(f"Manual check result for URL '{result_dict['url']}': Risk={result_dict['risk_score']}, Phishing={result_dict['is_phishing']}. Reasons: {'; '.join(result_dict['reasons'])}")

        if result_obj.is_phishing:
            self.phishing_detected_since_last_update +=1
            domain_to_block = urlparse(result_obj.url).hostname
            if domain_to_block:
                self.blocked_domains.add(domain_to_block) # Add to PhishingBlocker's active block list.
                self.detector.blacklisted_domains.add(domain_to_block) # Also add to detector's internal blacklist for future reference.
                self._save_to_file(self.user_blacklist_file, self.detector.blacklisted_domains) # Persist this change.
                result_dict["blocked"] = True # Update the result dictionary to reflect the blocking action.
                logger.info(f"Domain '{domain_to_block}' added to PhishingBlocker's active block list and persisted to user_blacklist.txt due to manual check confirmation.")
                # Note: send_block_notification is typically not called here as the client initiated the check
                # and will receive this detailed result_dict directly.
        
        return result_dict


    def is_blocked(self, host: str, ip: Optional[str] = None) -> bool: 
        """
        Checks if a given host (domain name) or IP address is currently present in the
        PhishingBlocker's active block lists (`self.blocked_domains` or `self.blocked_ips`).

        Args:
            host (str): The hostname (e.g., "example.com", "sub.example.org") to check.
            ip (Optional[str]): The IP address to check.

        Returns:
            bool: True if either the host or the IP address is found in the respective
                  block lists, False otherwise.
        """
        # Ensure host is just the hostname, not "host:port", for accurate lookup.
        # Prepending "http://" helps urlparse correctly identify the hostname part.
        parsed_host = urlparse(f"http://{host}").hostname 
        if not parsed_host: parsed_host = host # Fallback if urlparse returns an empty hostname (e.g., if host is already just an IP).

        if parsed_host in self.blocked_domains:
            return True
        if ip and ip in self.blocked_ips: # Only check the IP if it's provided.
            return True
        return False


    async def stop(self):
        """
        Gracefully shuts down the PhishingBlocker and its associated components.
        This involves:
        - Setting the `self.running` flag to False to signal background asyncio tasks to stop.
        - Cancelling the `stats_update_task` and `result_processor_task`.
        - Stopping the underlying `ClassicalPhishingDetector` (which manages its own resources,
          like a multiprocessing pool).
        - Closing the `aiohttp.ClientSession` if it was initialized.
        Logs the shutdown process at each step.
        """
        logger.info("Stopping PhishingBlocker and its components...")
        self.running.value = False  # Signal background asyncio tasks to stop their loops.

        # Cancel the stats update task.
        if self.stats_update_task and not self.stats_update_task.done():
            self.stats_update_task.cancel()
            try:
                await self.stats_update_task # Wait for the task to acknowledge cancellation.
            except asyncio.CancelledError:
                logger.info("Phishing statistics update task successfully cancelled.")
            except Exception as e: # Log other potential errors during task cancellation.
                logger.error(f"Error encountered while cancelling phishing_stats_update_task: {e}", exc_info=True)


        # Cancel the result_processor_task (which handles results from the detector's queue).
        if self.result_processor_task and not self.result_processor_task.done():
            self.result_processor_task.cancel()
            try:
                await self.result_processor_task # Wait for the task to acknowledge cancellation.
            except asyncio.CancelledError:
                logger.info("Result processor task successfully cancelled.")
            except Exception as e:
                logger.error(f"Error encountered while cancelling result_processor_task: {e}", exc_info=True)

        
        # Stop the ClassicalPhishingDetector (this method should handle its internal pool and queues).
        if self.detector:
            logger.info("Stopping ClassicalPhishingDetector component...")
            self.detector.stop() 
            logger.info("ClassicalPhishingDetector component stopped.")

        # Close the aiohttp client session if it was initialized and is still open.
        if self.http_session and not self.http_session.closed:
            logger.info("Closing aiohttp client session...")
            await self.http_session.close()
            logger.info("aiohttp client session closed.")
        
        logger.info("PhishingBlocker stopped successfully.")


# Helper function to convert PhishingResult to dict for SocketIO/logging consistency
def result_dict_from_obj(result_obj: PhishingResult) -> dict:
    """
    Converts a PhishingResult object to a standardized dictionary format.
    This is useful for ensuring consistent data structures when emitting data
    via Socket.IO or for logging purposes.

    Args:
        result_obj (PhishingResult): The PhishingResult object to convert.

    Returns:
        dict: A dictionary representation of the PhishingResult object.
    """
    return {
        "url": result_obj.url,
        "is_phishing": result_obj.is_phishing,
        "risk_score": result_obj.risk_score,
        "reasons": result_obj.reasons,
        "timestamp": result_obj.timestamp,
    }

