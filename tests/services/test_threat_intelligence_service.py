import unittest
from unittest.mock import patch, mock_open, MagicMock, call
import json
from datetime import datetime
import os
import requests  # Required for requests.exceptions.HTTPError

# Adjust the import path for the service based on execution context.
# Assuming tests are run from the repository root or PYTHONPATH is configured.
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService


class TestThreatIntelligenceService(unittest.TestCase):

    def setUp(self):
        self.cache_file_path = "test_threat_data_cache.json"
        # Ensure a clean state by removing the cache file if it exists
        if os.path.exists(self.cache_file_path):
            os.remove(self.cache_file_path)

    def tearDown(self):
        # Clean up the cache file after each test
        if os.path.exists(self.cache_file_path):
            os.remove(self.cache_file_path)

    def _get_mock_api_responses(self):
        mock_osint_response = MagicMock(spec=requests.Response)
        mock_osint_response.status_code = 200
        mock_osint_response.json.return_value = [
            {
                "ioc_id": "123",
                "ioc_value": "evil.com",
                "ioc_type": "domain",
                "threat_type_desc": "malware_family",
                "malware_printable": "EvilBot",
                "first_seen_utc": "2023-01-01T00:00:00Z",
                "last_seen_utc": "2023-01-02T00:00:00Z",
                "confidence_level": 90,
                "reference": "http://example.com/report",
                "tags": ["botnet"],
            }
        ]

        mock_cve_response = MagicMock(spec=requests.Response)
        mock_cve_response.status_code = 200
        mock_cve_response.json.return_value = [
            {
                "cveMetadata": {
                    "cveId": "CVE-2023-1234",  # Corrected ID for consistency with existing tests
                    "datePublished": "2023-01-01T00:00:00Z",
                    "dateUpdated": "2023-01-02T00:00:00Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Test CVE summary"}],
                        "references": [
                            {"url": "http://example.com/ref1"},
                            {"name": "ref2", "url": "http://example.com/ref2"},
                        ],
                    }
                },
                "cvss": 7.5,
            }
        ]
        return mock_osint_response, mock_cve_response

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_initial_load_if_cache_file_missing(self, mock_file_open, mock_get):
        mock_file_open.side_effect = [
            FileNotFoundError,  # First load fails
            mock_open(read_data="{}").return_value,  # _initialize_feed_metadata save
            mock_open(read_data="{}").return_value,  # osint save
            mock_open(read_data="{}").return_value,  # cve save
        ]

        mock_osint_response, mock_cve_response = self._get_mock_api_responses()
        mock_get.side_effect = [mock_osint_response, mock_cve_response]

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)

        self.assertIn("osint_feed", service.cache)
        self.assertIn("cve_feed", service.cache)
        self.assertTrue(len(service.cache["osint_feed"]["data"]) > 0)
        self.assertTrue(len(service.cache["cve_feed"]["data"]) > 0)
        mock_get.assert_any_call(
            "https://threatfox.abuse.ch/export/json/recent/", timeout=10
        )
        mock_get.assert_any_call("https://cve.circl.lu/api/last/10", timeout=10)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_initial_load_if_cve_data_invalid_and_osint_missing(
        self, mock_file_open, mock_get
    ):
        initial_cache_content = {
            "threatfox_meta": {
                "is_subscribed": True,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            },
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
            # Invalid CVE data: 'data' exists but first item has no 'id' (which our logic checks for `cveMetadata.cveId`)
            # For the new logic, this means the list is present, but its first item (if any) would fail the `[0].get("id") is None` check if 'id' was the key.
            # More accurately for the new logic, an item is invalid if `cveMetadata.cveId` is missing.
            # So, an empty list for 'data' or a list where items lack proper structure would trigger reload.
            # Let's use a structure that new logic would identify as invalid:
            "cve_feed": {
                "data": [{"cveMetadata": {"cveId": None}}],
                "last_updated": "sometime",
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
        }
        # Simulate reading this cache, then subsequent writes
        mock_file_open.side_effect = [
            mock_open(
                read_data=json.dumps(initial_cache_content)
            ).return_value,  # initial load
            mock_open(
                read_data=json.dumps(initial_cache_content)
            ).return_value,  # osint save
            mock_open(
                read_data=json.dumps(initial_cache_content)
            ).return_value,  # cve save
        ]

        mock_osint_response, mock_cve_response = self._get_mock_api_responses()
        # mock_cve_response is already in the new 5.0 format from _get_mock_api_responses
        mock_get.side_effect = [mock_osint_response, mock_cve_response]

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)

        self.assertIn("cve_feed", service.cache)
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["id"], "CVE-2023-1234"
        )  # Expecting the valid ID from mock
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["summary"], "Test CVE summary"
        )
        self.assertIn("osint_feed", service.cache)
        self.assertTrue(len(service.cache["osint_feed"]["data"]) > 0)
        mock_get.assert_any_call(
            "https://threatfox.abuse.ch/export/json/recent/", timeout=10
        )
        mock_get.assert_any_call("https://cve.circl.lu/api/last/10", timeout=10)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_initial_load_osint_valid_cve_invalid(self, mock_file_open, mock_get):
        mock_osint_data, _ = (
            self._get_mock_api_responses()
        )  # to get sample data structure
        initial_cache_content = {
            "threatfox_meta": {
                "is_subscribed": True,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            },
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
            "osint_feed": {
                "data": mock_osint_data.json.return_value,
                "last_updated": "sometime",
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            },
            # Invalid CVE data (missing cveId)
            "cve_feed": {
                "data": [{"cveMetadata": {"cveId": None}}],
                "last_updated": "sometime",
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
        }
        mock_file_open.side_effect = [
            mock_open(
                read_data=json.dumps(initial_cache_content)
            ).return_value,  # initial load
            mock_open(
                read_data=json.dumps(initial_cache_content)
            ).return_value,  # cve save
        ]

        _, mock_cve_response = self._get_mock_api_responses()
        # mock_cve_response is already in the new 5.0 format.
        mock_get.return_value = mock_cve_response  # Only CVE should be fetched

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)

        self.assertEqual(service.cache["cve_feed"]["data"][0]["id"], "CVE-2023-1234")
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["summary"], "Test CVE summary"
        )
        # Ensure OSINT data is still the original loaded data (mock_get was not called for OSINT)
        self.assertEqual(service.cache["osint_feed"]["data"][0]["ioc_id"], "123")
        mock_get.assert_called_once_with("https://cve.circl.lu/api/last/10", timeout=10)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_no_initial_load_if_data_valid(self, mock_file_open, mock_get):
        mock_osint_data, mock_cve_data = self._get_mock_api_responses()
        initial_cache_content = {
            "threatfox_meta": {"is_subscribed": True},
            "cve_circl_meta": {"is_subscribed": True},
            "osint_feed": {
                "data": mock_osint_data.json.return_value,
                "last_updated": "sometime",
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            },
            "cve_feed": {
                "data": mock_cve_data.json.return_value,
                "last_updated": "sometime",
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },  # mock_cve_data is already new format
        }
        mock_file_open.return_value = mock_open(
            read_data=json.dumps(initial_cache_content)
        ).return_value

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)

        mock_get.assert_not_called()  # Core assertion: fetch methods were not called
        self.assertEqual(service.cache["osint_feed"]["data"][0]["ioc_id"], "123")
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["id"], "CVE-2023-1234"
        )  # ID from new format mock
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["summary"], "Test CVE summary"
        )

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_fetch_cve_data_skips_items_without_id(self, mock_file_open, mock_get):
        mock_file_open.return_value = mock_open(
            read_data='{"cve_circl_meta": {"is_subscribed": True}}'
        ).return_value  # for _load_cache then _save_cache

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "cveMetadata": {"cveId": "CVE-2023-1"},
                "containers": {"cna": {"descriptions": [{"value": "First"}]}},
            },
            {
                "containers": {
                    "cna": {"descriptions": [{"value": "Missing cveMetadata"}]}
                }
            },
            {
                "cveMetadata": {},
                "containers": {"cna": {"descriptions": [{"value": "Missing cveId"}]}},
            },
        ]
        mock_get.return_value = mock_response

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)
        # Clear existing cache from constructor to test fetch_cve_data in isolation
        service.cache = {
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
            "cve_feed": {},
        }  # ensure cve_feed dict exists
        service.fetch_cve_data()

        self.assertIn("cve_feed", service.cache)
        self.assertEqual(len(service.cache["cve_feed"]["data"]), 1)
        self.assertEqual(service.cache["cve_feed"]["data"][0]["id"], "CVE-2023-1")
        self.assertEqual(service.cache["cve_feed"]["data"][0]["summary"], "First")

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_fetch_cve_data_api_error(self, mock_file_open, mock_get):
        mock_file_open.return_value = mock_open(
            read_data='{"cve_circl_meta": {"is_subscribed": True}}'
        ).return_value

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 500
        mock_response.response = mock_response  # for e.response.status_code
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "API Error"
        )
        mock_get.return_value = mock_response

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)
        service.cache = {
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            }
        }
        result = service.fetch_cve_data()

        self.assertEqual(result["status"], "error")
        self.assertIn("cve_feed", service.cache)
        self.assertIn("error", service.cache["cve_feed"])
        self.assertEqual(len(service.cache["cve_feed"].get("data", [])), 0)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_fetch_cve_data_json_decode_error(self, mock_file_open, mock_get):
        mock_file_open.return_value = mock_open(
            read_data='{"cve_circl_meta": {"is_subscribed": True}}'
        ).return_value

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        mock_get.return_value = mock_response

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)
        service.cache = {
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            }
        }
        result = service.fetch_cve_data()

        self.assertEqual(result["status"], "error")
        self.assertIn("cve_feed", service.cache)
        self.assertEqual(service.cache["cve_feed"].get("error"), "JSON parsing error")
        self.assertEqual(len(service.cache["cve_feed"].get("data", [])), 0)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_fetch_osint_data_api_error(self, mock_file_open, mock_get):
        mock_file_open.return_value = mock_open(
            read_data='{"threatfox_meta": {"is_subscribed": True}}'
        ).return_value

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 503
        mock_response.response = mock_response
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "Service Unavailable"
        )
        mock_get.return_value = mock_response

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)
        service.cache = {
            "threatfox_meta": {
                "is_subscribed": True,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            }
        }
        result = service.fetch_osint_feed()

        self.assertEqual(result["status"], "error")
        self.assertIn("osint_feed", service.cache)
        self.assertIn("error", service.cache["osint_feed"])
        self.assertEqual(len(service.cache["osint_feed"].get("data", [])), 0)

    @patch("backend.app.services.threat_intelligence_service.requests.get")
    @patch(
        "backend.app.services.threat_intelligence_service.open", new_callable=mock_open
    )
    def test_update_subscription_and_refresh(self, mock_file_open, mock_get):
        # Initial cache: both subscribed, osint has data, cve needs load
        mock_osint_response, _ = self._get_mock_api_responses()
        initial_cache_data = {
            "threatfox_meta": {
                "is_subscribed": True,
                "name": "ThreatFox IOCs",
                "id": "threatfox",
            },
            "osint_feed": {
                "data": mock_osint_response.json.return_value,
                "last_updated": "prev_time",
            },
            "cve_circl_meta": {
                "is_subscribed": True,
                "name": "CIRCL CVEs",
                "id": "cve_circl",
            },
            # cve_feed missing, so it will be loaded by initial_data_load
        }

        # Mock file operations: load initial, then saves during updates/refreshes
        # This needs to be more dynamic if many saves happen.
        # For simplicity, assume one load and then subsequent saves are fine.
        mock_file_open.return_value = mock_open(
            read_data=json.dumps(initial_cache_data)
        ).return_value

        # Mock API responses
        # 1. For initial CVE load
        # 2. For CVE refresh after re-subscribing
        _, mock_cve_response_initial = (
            self._get_mock_api_responses()
        )  # Already in new format

        mock_cve_response_refresh_json = {
            "cveMetadata": {
                "cveId": "CVE-REFRESHED-OK",
                "datePublished": "2023-03-01T00:00:00Z",
            },
            "containers": {
                "cna": {"descriptions": [{"value": "Refreshed CVE summary"}]}
            },
            "cvss": 8.0,
        }
        mock_cve_response_refresh = MagicMock(spec=requests.Response)
        mock_cve_response_refresh.status_code = 200
        mock_cve_response_refresh.json.return_value = [mock_cve_response_refresh_json]

        mock_get.side_effect = [mock_cve_response_initial, mock_cve_response_refresh]

        service = ThreatIntelligenceService(cache_file_path=self.cache_file_path)

        # Ensure initial state is as expected (OSINT loaded from cache, CVE loaded via initial_data_load)
        self.assertEqual(service.cache["osint_feed"]["data"][0]["ioc_id"], "123")
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["id"], "CVE-2023-1234"
        )  # From initial load
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["summary"], "Test CVE summary"
        )
        self.assertTrue(service.cache["cve_circl_meta"]["is_subscribed"])

        # Unsubscribe from CVE
        service.update_feed_subscription(feed_id="cve_circl", is_subscribed=False)
        self.assertFalse(service.cache["cve_circl_meta"]["is_subscribed"])

        # Re-subscribe to CVE - this should trigger a refresh
        service.update_feed_subscription(feed_id="cve_circl", is_subscribed=True)
        self.assertTrue(service.cache["cve_circl_meta"]["is_subscribed"])
        self.assertEqual(service.cache["cve_feed"]["data"][0]["id"], "CVE-REFRESHED-OK")
        self.assertEqual(
            service.cache["cve_feed"]["data"][0]["summary"], "Refreshed CVE summary"
        )

        # Check calls to requests.get:
        # 1. Initial load of CVEs
        # 2. Refresh of CVEs after re-subscribing
        expected_calls = [
            call("https://cve.circl.lu/api/last/10", timeout=10),  # Initial load
            call("https://cve.circl.lu/api/last/10", timeout=10),  # Refresh
        ]
        mock_get.assert_has_calls(expected_calls)
        self.assertEqual(mock_get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
