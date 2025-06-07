import logging
import json
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    def __init__(self, cache_file_path="threat_data_cache.json"):
        self.cache_file_path = cache_file_path
        self.cache = self._load_cache()
        # Ensure default subscription statuses are set if not present
        self._initialize_feed_metadata()
        osint_feed_data = self.cache.get("osint_feed", {}).get("data")
        cve_feed_data = self.cache.get("cve_feed", {}).get("data")

        # Check if either feed is missing or its data is empty or seems like placeholder (e.g., list of nulls for CVEs)
        needs_osint_load = not osint_feed_data
        # For CVE, check if data is present and if the first item has an ID (assuming valid items always have IDs)
        needs_cve_load = not cve_feed_data or (
            isinstance(cve_feed_data, list)
            and cve_feed_data
            and cve_feed_data[0].get("id") is None
        )

        if needs_osint_load or needs_cve_load:
            logger.info(
                "Performing initial data load due to missing or invalid feed data in cache."
            )
            self.initial_data_load(
                force_osint=needs_osint_load, force_cve=needs_cve_load
            )

    def _initialize_feed_metadata(self):
        """Initializes metadata like subscription status for feeds if not already present."""
        changed = False
        if "threatfox_meta" not in self.cache:
            self.cache["threatfox_meta"] = {
                "is_subscribed": True,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            }
            changed = True
        if "cve_circl_meta" not in self.cache:
            self.cache["cve_circl_meta"] = {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            }
            changed = True
        if changed:
            self._save_cache(self.cache)

    def _load_cache(self):
        try:
            with open(self.cache_file_path, "r") as f:
                cache_data = json.load(f)
                logger.info(f"Cache loaded from {self.cache_file_path}")
                return cache_data
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(
                f"Cache file not found or invalid, attempting to initialize new cache: {e}"
            )
            # Initialize with empty cache and basic metadata structure
            new_cache = {}
            self._save_cache(new_cache)  # save empty cache first
            # Now call _initialize_feed_metadata which operates on self.cache
            # self.cache = new_cache # Temporarily set self.cache for _initialize_feed_metadata
            # self._initialize_feed_metadata() # This will save again.
            # Let's simplify: just return empty and let constructor handle init.
            return {}

    def _save_cache(self, data):
        try:
            with open(self.cache_file_path, "w") as f:
                json.dump(data, f, indent=4)
            logger.info(f"Cache saved to {self.cache_file_path}")
        except IOError as e:
            logger.error(f"Error saving cache to {self.cache_file_path}: {e}")

    def initial_data_load(self, force_osint=True, force_cve=True):
        logger.info(
            f"Performing initial data load. Force OSINT: {force_osint}, Force CVE: {force_cve}"
        )
        if force_osint:
            if self.cache.get("threatfox_meta", {}).get("is_subscribed", True):
                self.fetch_osint_feed()
            else:
                logger.info("Skipping OSINT feed load as it's not subscribed.")
        else:
            logger.info(
                "OSINT feed data seems valid in cache, skipping initial load unless forced."
            )

        if force_cve:
            if self.cache.get("cve_circl_meta", {}).get("is_subscribed", True):
                self.fetch_cve_data()
            else:
                logger.info("Skipping CVE feed load as it's not subscribed.")
        else:
            logger.info(
                "CVE feed data seems valid in cache, skipping initial load unless forced."
            )
        logger.info("Initial data load process complete.")

    def fetch_osint_feed(self):
        # Ensure that we only fetch if subscribed
        if not self.cache.get("threatfox_meta", {}).get("is_subscribed", True):
            logger.info("ThreatFox feed is unsubscribed. Skipping fetch.")
            return {"status": "skipped", "reason": "unsubscribed", "data": []}

        logger.info("Fetching OSINT feed from ThreatFox...")
        url = "https://threatfox.abuse.ch/export/json/recent/"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()

            # --- Start Debugging Additions ---
            logger.info(
                f"OSINT feed: Type of raw 'data' from response.json(): {type(data)}"
            )
            if isinstance(data, list):
                logger.info(f"OSINT feed: 'data' is a list. Length: {len(data)}")
                if len(data) > 0:
                    logger.info(
                        f"OSINT feed: Type of first element in 'data': {type(data[0])}"
                    )
            elif isinstance(data, dict):
                logger.info(f"OSINT feed: 'data' is a dict. Keys: {list(data.keys())}")
            else:
                logger.info(
                    f"OSINT feed: 'data' is neither a list nor a dict. It is: {str(data)[:200]}"
                )  # Log first 200 chars

            test_slice = None
            try:
                processed_items = []
                for value in data.values():
                    if isinstance(value, dict):
                        # If the value is already a dictionary, add it
                        processed_items.append(value)
                    elif isinstance(value, list):
                        # If the value is a list, iterate through its elements
                        for sub_item in value:
                            if isinstance(sub_item, dict):
                                # If a sub-item is a dictionary, add it
                                processed_items.append(sub_item)
                    # Stop if we've collected enough items for the debug slice
                    if len(processed_items) >= 50:
                        break
                test_slice = processed_items[:50] # Ensures we only take up to 50 items
                logger.info(
                    f"OSINT feed: Type of 'test_slice' (data[:50]): {type(test_slice)}"
                )
                if isinstance(test_slice, list):
                    logger.info(
                        f"OSINT feed: 'test_slice' is a list. Length: {len(test_slice)}"
                    )
                    if len(test_slice) > 0:
                        logger.info(
                            f"OSINT feed: Type of first element in 'test_slice': {type(test_slice[0])}"
                        )
                else:
                    logger.info(
                        f"OSINT feed: 'test_slice' is not a list. It is: {str(test_slice)[:200]}"
                    )

            except TypeError as slice_err:
                logger.error(
                    f"OSINT feed: Error when trying to slice 'data': {slice_err}",
                    exc_info=True,
                )
                # If slicing fails, we can't proceed with the loop as it was.
                # Return error, or an empty list if appropriate.
                self.cache["osint_feed"] = {
                    "error": f"Slicing error: {slice_err}",
                    "last_updated": datetime.utcnow().isoformat(),
                    "source_url": url,
                    "name": "ThreatFox IOCs",
                    "id": "threatfox",
                    "data": [],
                }
                self._save_cache(self.cache)
                return {
                    "error": f"Slicing error: {slice_err}",
                    "status": "error",
                    "data": [],
                }
            # --- End Debugging Additions ---

            # Original logger info line, now after debug logs
            logger.info(
                f"OSINT feed: Received {len(data) if isinstance(data, list) else 'N/A'} items from API. Processing up to 50."
            )

            structured_data = []
            processed_item_count = 0

            # Temporarily simplified loop for debugging the "unhashable type: 'slice'" error
            # The goal is to see if the error happens during iteration setup or first item access
            if isinstance(
                test_slice, list
            ):  # Use the test_slice we already made and type-checked
                logger.info(
                    f"OSINT feed: Starting simplified debug loop with 'test_slice' of length {len(test_slice)}."
                )
                for item_index, item in enumerate(test_slice):
                    try:
                        logger.info(
                            f"OSINT feed (Debug Loop): Processing item {item_index}, type: {type(item)}"
                        )
                        if isinstance(item, dict):
                            # Perform a very simple operation, like trying to get a known key
                            # This is to check if 'item' itself is problematic or if its contents are.
                            # Example: just logging keys to see their types.
                            # for k_debug, v_debug in item.items():
                            #    logger.debug(f"Item {item_index} key: {k_debug} (type {type(k_debug)})")

                            # The following is the original processing logic, now inside this debug try-except
                            tags_data = item.get("tags")
                            if isinstance(tags_data, list):
                                processed_tags = [
                                    str(tag)
                                    for tag in tags_data
                                    if isinstance(tag, (str, int, float, bool))
                                ]
                            elif tags_data is not None:
                                logger.warning(
                                    f"OSINT item {item_index} 'tags' field was not a list, got {type(tags_data)}. Item: {str(item)[:200]}"
                                )
                                processed_tags = []
                            else:
                                processed_tags = []

                            indicator_data = {
                                "ioc_id": (
                                    str(item.get("ioc_id"))
                                    if item.get("ioc_id") is not None
                                    else None
                                ),
                                "indicator": (
                                    str(item.get("ioc_value"))
                                    if item.get("ioc_value") is not None
                                    else None
                                ),
                                "type": (
                                    str(item.get("ioc_type"))
                                    if item.get("ioc_type") is not None
                                    else None
                                ),
                                "threat_type": (
                                    str(item.get("threat_type_desc"))
                                    if item.get("threat_type_desc") is not None
                                    else None
                                ),
                                "malware": (
                                    str(item.get("malware_printable"))
                                    if item.get("malware_printable") is not None
                                    else None
                                ),
                                "source": "ThreatFox",
                                "first_seen": (
                                    str(item.get("first_seen_utc"))
                                    if item.get("first_seen_utc") is not None
                                    else None
                                ),
                                "last_seen": (
                                    str(item.get("last_seen_utc"))
                                    if item.get("last_seen_utc") is not None
                                    else None
                                ),
                                "confidence": item.get("confidence_level"),
                                "reference": (
                                    str(item.get("reference"))
                                    if item.get("reference") is not None
                                    else None
                                ),
                                "tags": processed_tags,
                            }
                            structured_data.append(
                                indicator_data
                            )  # Add to the original structured_data
                            processed_item_count += 1
                        else:
                            logger.warning(
                                f"OSINT feed (Debug Loop): Item {item_index} is not a dict, it is {type(item)}. Skipping."
                            )

                        # For debugging, let's try to process only a few items to see if error occurs early
                        # if item_index >= 4 : # Process first 5 items then break
                        #    logger.info("OSINT feed (Debug Loop): Processed 5 items, breaking for debug.")
                        #    break

                    except Exception as item_processing_exc:
                        logger.error(
                            f"OSINT feed (Debug Loop): Error processing item {item_index}. Error: {item_processing_exc}. Item: {str(item)[:500]}",
                            exc_info=True,
                        )  # Log more of the item
                        # Continue to the next item to see if others succeed
                        continue
                logger.info("OSINT feed (Debug Loop): Finished simplified loop.")
            else:
                logger.error(
                    "OSINT feed: 'test_slice' was not a list, cannot perform loop processing."
                )
                # This case should have been caught by the slice_err block earlier if data[:50] failed.
                # If it's not a list here, it means data[:50] returned something other than a list but didn't raise TypeError.

            if not structured_data:
                logger.warning(
                    "OSINT feed: No structured data was generated after processing items. This might be due to an empty API response or all items failing processing. Cache will not be updated with empty data."
                )
                return {
                    "status": "error",
                    "reason": "no data processed or all items failed",
                    "data": [],
                }

            self.cache["osint_feed"] = {
                "data": structured_data,  # Use the data populated by the loop
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "ThreatFox IOCs",  # Added for consistency
                "id": "threatfox",
            }
            self._save_cache(self.cache)
            logger.info(
                f"Successfully fetched and cached OSINT feed. {len(structured_data)} items processed."
            )
            return self.cache["osint_feed"]
        except requests.RequestException as e:
            status_code = e.response.status_code if e.response is not None else "N/A"
            logger.error(
                f"Error fetching OSINT feed from {url}. Status code: {status_code}. Error: {e}"
            )
            self.cache["osint_feed"] = {
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
                "data": [],
            }
            self._save_cache(self.cache)
            return {"error": str(e), "status": "error", "data": []}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from OSINT feed {url}: {e}")
            self.cache["osint_feed"] = {
                "error": "JSON parsing error",
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
                "data": [],
            }
            self._save_cache(self.cache)
            return {"error": "JSON parsing error", "status": "error", "data": []}
        except Exception as e:  # This is the generic catch-all
            logger.error(
                f"An unexpected error occurred while fetching OSINT feed: {e}",
                exc_info=True,
            )  # Added exc_info=True
            # Try to save minimal error info to cache if possible
            if hasattr(self, "cache") and isinstance(
                self.cache, dict
            ):  # Check if cache exists and is a dict
                self.cache["osint_feed"] = {
                    "error": f"Unexpected error: {e}",
                    "last_updated": datetime.utcnow().isoformat(),
                    "source_url": url,
                    "name": "ThreatFox IOCs",
                    "id": "threatfox",
                    "data": [],
                }
                self._save_cache(self.cache)
            return {"error": str(e), "status": "error", "data": []}

    def fetch_cve_data(self):
        # Ensure that we only fetch if subscribed
        if not self.cache.get("cve_circl_meta", {}).get("is_subscribed", True):
            logger.info("CIRCL CVE feed is unsubscribed. Skipping fetch.")
            return {"status": "skipped", "reason": "unsubscribed", "data": []}

        logger.info("Fetching CVE data from cve.circl.lu...")
        url = "https://cve.circl.lu/api/last/10"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            structured_data = []
            if isinstance(data, list):
                for item_index, item in enumerate(
                    data
                ):  # Iterate with index for better logging
                    try:
                        cve_id = None
                        if isinstance(item.get("cveMetadata"), dict):
                            cve_id = item["cveMetadata"].get("cveId")

                        if not cve_id:
                            # Log the problematic item structure if ID is missing
                            # logger.warning(f"Skipping CVE item at index {item_index} due to missing cveMetadata.cveId. Item keys: {list(item.keys()) if isinstance(item, dict) else 'Not a dict'}")
                            # More detailed log based on user feedback:
                            logger.warning(
                                f"Skipping CVE item at index {item_index} due to missing ID. Full item: {json.dumps(item, indent=2)}"
                            )  # Log the full item
                            continue

                        summary = None
                        if (
                            isinstance(item.get("containers"), dict)
                            and isinstance(item["containers"].get("cna"), dict)
                            and isinstance(
                                item["containers"]["cna"].get("descriptions"), list
                            )
                            and item["containers"]["cna"]["descriptions"]
                        ):
                            summary = item["containers"]["cna"]["descriptions"][0].get(
                                "value"
                            )

                        published_date = item.get("cveMetadata", {}).get(
                            "datePublished"
                        )
                        modified_date = item.get("cveMetadata", {}).get(
                            "dateUpdated"
                        )  # Or dateModified if that's the field

                        cvss_score = None
                        # CIRCL often provides 'cvss' directly, or it might be in 'metrics'
                        raw_cvss = item.get("cvss")
                        if isinstance(raw_cvss, (float, int)):
                            cvss_score = float(raw_cvss)
                        elif isinstance(
                            raw_cvss, str
                        ):  # If CVSS is a string like "7.5"
                            try:
                                cvss_score = float(raw_cvss)
                            except ValueError:
                                logger.warning(
                                    f"Could not parse CVSS string '{raw_cvss}' for {cve_id}"
                                )
                        # If CVSS is nested, e.g., in item.get('containers',{}).get('cna',{}).get('metrics',[])
                        # This part might need more complex parsing based on actual data structure if 'cvss' top-level field is not reliable
                        # For now, relying on item.get('cvss')

                        references_list = []
                        raw_references = item.get("references")  # NVD format
                        if isinstance(raw_references, list):
                            for ref in raw_references:
                                if isinstance(ref, dict) and ref.get("url"):
                                    references_list.append(ref["url"])
                                elif isinstance(
                                    ref, str
                                ):  # Sometimes references are just a list of strings
                                    references_list.append(ref)
                        # For CIRCL, references might be item.get('containers',{}).get('cna',{}).get('references',[])
                        if (
                            not references_list
                            and isinstance(item.get("containers"), dict)
                            and isinstance(item["containers"].get("cna"), dict)
                            and isinstance(
                                item["containers"]["cna"].get("references"), list
                            )
                        ):
                            cna_references = item["containers"]["cna"]["references"]
                            for ref in cna_references:
                                if isinstance(ref, dict) and ref.get("url"):
                                    references_list.append(ref["url"])
                                elif isinstance(ref, str):
                                    references_list.append(ref)

                        cve_entry_data = {
                            "id": cve_id,
                            "summary": summary,
                            "published": published_date,
                            "modified": modified_date,
                            "cvss": cvss_score,
                            "references": references_list,
                        }
                        structured_data.append(cve_entry_data)
                    except Exception as item_exc:
                        logger.error(
                            f"CVE feed: Error processing item at index {item_index}. Error: {item_exc}. Item: {json.dumps(item, indent=2)}",
                            exc_info=True,
                        )
                        continue  # Skip this item

            if not structured_data:
                logger.warning(
                    "CVE feed: No valid structured data was generated (all items might have been skipped or API response was empty). Cache will not be updated with empty data."
                )
                return {
                    "status": "error",
                    "reason": "no valid data processed",
                    "data": [],
                }

            self.cache["cve_feed"] = {
                "data": structured_data,
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "CIRCL CVEs",  # Added for consistency
                "id": "cve_circl",
            }
            self._save_cache(self.cache)
            logger.info(
                f"Successfully fetched and cached CVE data. {len(structured_data)} items processed."
            )
            return self.cache["cve_feed"]
        except requests.RequestException as e:
            status_code = e.response.status_code if e.response is not None else "N/A"
            logger.error(
                f"Error fetching CVE data from {url}. Status code: {status_code}. Error: {e}"
            )
            self.cache["cve_feed"] = {
                "error": str(e),
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
                "data": [],
            }
            self._save_cache(self.cache)
            return {"error": str(e), "status": "error", "data": []}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from CVE feed {url}: {e}")
            self.cache["cve_feed"] = {
                "error": "JSON parsing error",
                "last_updated": datetime.utcnow().isoformat(),
                "source_url": url,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
                "data": [],
            }
            self._save_cache(self.cache)
            return {"error": "JSON parsing error", "status": "error", "data": []}
        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching CVE feed: {e}")
            return {"error": str(e), "status": "error", "data": []}

    def get_emerging_threats(self):
        logger.info("Getting emerging threats from subscribed and available feeds...")
        emerging_threats = []

        # CVEs
        cve_meta = self.cache.get("cve_circl_meta", {})
        if cve_meta.get("is_subscribed", True):
            if "cve_feed" in self.cache and self.cache["cve_feed"].get("data"):
                for cve in self.cache["cve_feed"]["data"][:2]:  # First 2 as example
                    emerging_threats.append(
                        {
                            "type": "CVE",
                            "id": cve.get("id"),
                            "summary": cve.get("summary"),
                            "published": cve.get("published"),
                            "source": "cve.circl.lu",
                        }
                    )
            else:
                logger.info(
                    "CVE feed data not available for emerging threats (or feed empty)."
                )
        else:
            logger.info("CVE feed is not subscribed, skipping for emerging threats.")

        # OSINT indicators
        osint_meta = self.cache.get("threatfox_meta", {})
        if osint_meta.get("is_subscribed", True):
            if "osint_feed" in self.cache and self.cache["osint_feed"].get("data"):
                for indicator in self.cache["osint_feed"]["data"]:
                    if indicator.get("confidence", 0) > 75:  # High confidence
                        emerging_threats.append(
                            {
                                "type": "OSINT Indicator",
                                "indicator": indicator.get("indicator"),
                                "indicator_type": indicator.get("type"),
                                "threat_type": indicator.get("threat_type"),
                                "source": indicator.get("source"),
                                "last_seen": indicator.get("last_seen"),
                            }
                        )
                        if len(emerging_threats) >= 5:  # Limit total emerging threats
                            break
            else:
                logger.info(
                    "OSINT feed data not available for emerging threats (or feed empty)."
                )
        else:
            logger.info("OSINT feed is not subscribed, skipping for emerging threats.")

        logger.info(f"Returning {len(emerging_threats)} emerging threats.")
        return emerging_threats

    def get_feeds(self):
        logger.info("Getting feeds status including subscription info...")
        feeds_status = []

        # ThreatFox OSINT Feed
        osint_meta = self.cache.get(
            "threatfox_meta",
            {"is_subscribed": True, "name": "ThreatFox IOCs", "id": "threatfox"},
        )  # Default if meta somehow missing
        osint_data = self.cache.get("osint_feed", {})
        feeds_status.append(
            {
                "id": osint_meta.get("id", "threatfox"),
                "name": osint_meta.get("name", "ThreatFox IOCs"),
                "status": (
                    "active"
                    if osint_data.get("data")
                    else ("error" if osint_data.get("error") else "pending/unfetched")
                ),
                "entries": len(osint_data.get("data", [])),
                "last_updated": osint_data.get("last_updated"),
                "source_url": osint_data.get(
                    "source_url", "https://threatfox.abuse.ch/export/json/recent/"
                ),
                "is_subscribed": osint_meta.get("is_subscribed", True),
            }
        )

        # CIRCL CVE Feed
        cve_meta = self.cache.get(
            "cve_circl_meta",
            {"is_subscribed": True, "name": "CIRCL CVEs", "id": "cve_circl"},
        )  # Default if meta somehow missing
        cve_data = self.cache.get("cve_feed", {})
        feeds_status.append(
            {
                "id": cve_meta.get("id", "cve_circl"),
                "name": cve_meta.get("name", "CIRCL CVEs"),
                "status": (
                    "active"
                    if cve_data.get("data")
                    else ("error" if cve_data.get("error") else "pending/unfetched")
                ),
                "entries": len(cve_data.get("data", [])),
                "last_updated": cve_data.get("last_updated"),
                "source_url": cve_data.get(
                    "source_url", "https://cve.circl.lu/api/last/10"
                ),
                "is_subscribed": cve_meta.get("is_subscribed", True),
            }
        )

        return feeds_status

    def update_feed_subscription(self, feed_id: str, is_subscribed: bool):
        logger.info(f"Updating feed subscription for {feed_id} to {is_subscribed}...")
        self.cache = self._load_cache()  # Ensure fresh cache

        meta_key = None
        if feed_id == "threatfox":
            meta_key = "threatfox_meta"
        elif feed_id == "cve_circl":
            meta_key = "cve_circl_meta"
        else:
            logger.warning(
                f"Subscription update requested for unknown feed ID: {feed_id}"
            )
            return {"error": f"Feed ID {feed_id} not found for subscription update."}

        if (
            meta_key not in self.cache
        ):  # Should have been initialized by _initialize_feed_metadata
            self.cache[meta_key] = {
                "id": feed_id,
                "name": "Unknown Feed",
            }  # Basic default

        self.cache[meta_key]["is_subscribed"] = is_subscribed
        self._save_cache(self.cache)

        logger.info(f"Subscription status for {feed_id} set to {is_subscribed}.")

        # If subscribing, fetch data immediately
        if is_subscribed:
            logger.info(f"Fetching data for newly subscribed feed: {feed_id}")
            self.refresh_feed_data(feed_id)  # This will also save the cache
        else:  # If unsubscribing, we could clear the data, or leave it stale.
            # Current behavior: leave data, it just won't be updated or used for emerging threats.
            logger.info(
                f"Feed {feed_id} unsubscribed. Data will not be actively refreshed."
            )

        updated_feed_info = (
            self.get_feeds()
        )  # Get the full list to find the specific feed
        for feed_info in updated_feed_info:
            if feed_info["id"] == feed_id:
                return feed_info  # Return the updated feed status
        return {
            "error": "Failed to retrieve updated feed status after subscription change."
        }

    def refresh_feed_data(self, feed_id: str):
        logger.info(f"Refreshing feed data for {feed_id} if subscribed...")
        feed_meta_key = None
        fetch_function = None

        if feed_id == "threatfox":
            feed_meta_key = "threatfox_meta"
            fetch_function = self.fetch_osint_feed
        elif feed_id == "cve_circl":
            feed_meta_key = "cve_circl_meta"
            fetch_function = self.fetch_cve_data
        else:
            logger.warning(f"Refresh requested for unknown feed ID: {feed_id}")
            return {
                "feed_id": feed_id,
                "status": "error",
                "error": f"Feed ID {feed_id} not recognized for refresh.",
            }

        # Check subscription status from metadata
        if self.cache.get(feed_meta_key, {}).get("is_subscribed", True):
            logger.info(f"Proceeding with refresh for subscribed feed: {feed_id}")
            result = fetch_function()  # This function should save the cache

            # Construct response based on fetch result
            if isinstance(result, dict) and result.get("status") == "error":
                return {
                    "feed_id": feed_id,
                    "status": "error",
                    "error": result.get("error", "Unknown error during fetch"),
                    "last_updated": None,
                }
            elif isinstance(result, dict) and result.get("status") == "skipped":
                return {
                    "feed_id": feed_id,
                    "status": "skipped",
                    "message": result.get("reason"),
                    "last_updated": None,
                }
            else:  # Assuming success
                last_updated_ts = None
                if feed_id == "threatfox" and "osint_feed" in self.cache:
                    last_updated_ts = self.cache["osint_feed"].get("last_updated")
                elif feed_id == "cve_circl" and "cve_feed" in self.cache:
                    last_updated_ts = self.cache["cve_feed"].get("last_updated")
                return {
                    "feed_id": feed_id,
                    "status": "refreshed",
                    "last_updated": last_updated_ts,
                    "entry_count": (
                        len(result.get("data", []))
                        if isinstance(result, dict)
                        else None
                    ),
                }
        else:
            logger.info(f"Feed {feed_id} is not subscribed. Skipping refresh.")
            return {
                "feed_id": feed_id,
                "status": "skipped",
                "message": "Feed is not subscribed.",
                "last_updated": None,
            }
