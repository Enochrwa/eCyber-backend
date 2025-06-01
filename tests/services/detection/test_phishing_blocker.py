import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock, mock_open
import os
import json
from datetime import datetime, timedelta
import time

# Make sure aiohttp is importable or mocked for tests
try:
    import aiohttp
except ImportError:
    aiohttp = MagicMock()
    aiohttp.ClientSession = MagicMock()
    aiohttp.ClientTimeout = MagicMock()
    aiohttp.ClientError = Exception
    aiohttp.ClientResponseError = Exception


from app.services.detection.phishing_blocker import PhishingBlocker, DATA_DIR
from app.services.detection.phishing_detector import (
    ClassicalPhishingDetector,
    PhishingResult,
)

# To handle socketio.AsyncClient if it's not available during tests without full app setup
try:
    import socketio
except ImportError:
    socketio = MagicMock()
    socketio.AsyncClient = MagicMock  # Mock the class itself


class TestPhishingBlocker(unittest.IsolatedAsyncioTestCase):

    @patch("app.services.detection.phishing_blocker.ClassicalPhishingDetector")
    @patch(
        "app.services.detection.phishing_blocker.socketio.AsyncClient"
    )  # Or Client if not async
    async def asyncSetUp(self, MockSioClient, MockClassicalPhishingDetector):
        self.mock_sio_client = MockSioClient()
        # self.mock_sio_client.start_background_task = MagicMock(side_effect=lambda target, *args, **kwargs: asyncio.create_task(target(*args, **kwargs)))
        # Correctly mock start_background_task to actually run the task if needed for some tests,
        # or just to check it's called for others. For now, a simple MagicMock is fine.
        self.mock_sio_client.start_background_task = MagicMock()

        self.mock_detector_instance = MockClassicalPhishingDetector.return_value
        self.mock_detector_instance.result_queue = (
            asyncio.Queue()
        )  # Mock the detector's queue for process_detection_results tests

        # Mock file system operations
        self.mock_os_path_exists = patch("os.path.exists").start()
        self.mock_os_makedirs = patch("os.makedirs").start()
        self.mock_open_func = patch("builtins.open", new_callable=mock_open).start()

        # Default behavior for os.path.exists
        self.mock_os_path_exists.return_value = (
            False  # Assume files don't exist by default
        )

        # Initialize PhishingBlocker
        # The PhishingBlocker's __init__ calls methods that use these mocks
        self.blocker = PhishingBlocker(self.mock_sio_client)

        # Replace the detector instance created by PhishingBlocker with our mock for more control in tests
        # This is important if the real detector makes network calls or has complex state
        self.blocker.detector = self.mock_detector_instance

        # Mock aiohttp.ClientSession specifically for the blocker's http_session
        self.mock_http_session = MagicMock(spec=aiohttp.ClientSession)
        self.mock_http_session.closed = False
        self.mock_http_session.get = AsyncMock()  # For process_http_activity
        self.mock_http_session.close = AsyncMock()  # For stop method

        # Simulate that _initialize_http_session assigns this mock
        # One way is to patch PhishingBlocker._initialize_http_session or directly set self.blocker.http_session
        # For simplicity in setup, we can assume _initialize_http_session will be called and set up self.blocker.http_session
        # Or, we can directly assign it if _initialize_http_session is simple enough or also mocked.
        self.blocker.http_session = self.mock_http_session

        # Ensure tasks are cleaned up
        self.addAsyncCleanup(self.asyncTearDown)

    async def asyncTearDown(self):
        # Stop PhishingBlocker to cancel its tasks
        if self.blocker and self.blocker.running.value:
            await self.blocker.stop()

        # Stop all patchers started with patch().start()
        patch.stopall()
        # Reset any global mocks if necessary, e.g., if Levenshtein was globally patched for detector tests
        # For now, assuming mocks are instance-specific or managed by patchers.

    # --- Initialization Tests ---
    def test_initialization_creates_data_dir_and_files(self):
        # Reset mocks for this specific test to check creation logic
        self.mock_os_path_exists.reset_mock()
        self.mock_os_makedirs.reset_mock()
        self.mock_open_func.reset_mock()

        # Simulate data directory and some files not existing
        def side_effect_exists(path):
            if path == DATA_DIR:
                return False
            if path == self.blocker.user_whitelist_file:
                return False
            if path == self.blocker.user_blacklist_file:
                return False
            if path == self.blocker.external_blacklist_files[0]:
                return False
            return True  # Other paths might exist

        self.mock_os_path_exists.side_effect = side_effect_exists

        # Re-initialize or call the parts of init that handle file creation
        # For this test, we'll focus on _ensure_data_dir_exists and what it implies for _load_from_file
        self.blocker._ensure_data_dir_exists()  # This is called in __init__

        self.mock_os_makedirs.assert_called_once_with(DATA_DIR)

        # Check that open was called to create each non-existent file
        expected_files_to_create = [
            self.blocker.user_whitelist_file,
            self.blocker.user_blacklist_file,
        ] + self.blocker.external_blacklist_files

        for f_path in expected_files_to_create:
            self.mock_open_func.assert_any_call(f_path, "w")

    def test_initialization_loads_persistent_lists(self):
        # Simulate files existing and containing some data
        self.mock_os_path_exists.side_effect = lambda path: True  # All files exist

        mock_whitelist_content = "whitelisted.com\n*.trustedsubdomain.com\n"
        mock_blacklist_content = "blacklisted.com\nphishy.org\n"

        # Configure mock_open to return different content for different files
        def mock_open_side_effect(file_path, mode="r"):
            if file_path == self.blocker.user_whitelist_file:
                return mock_open(read_data=mock_whitelist_content).return_value
            elif file_path == self.blocker.user_blacklist_file:
                return mock_open(read_data=mock_blacklist_content).return_value
            elif (
                file_path in self.blocker.external_blacklist_files
            ):  # For external lists
                return mock_open(read_data="externalbad.com\n").return_value
            return mock_open(read_data="").return_value  # Default for other files

        self.mock_open_func.side_effect = mock_open_side_effect

        # Call the loading methods (they are called in __init__, but we can call again to assert)
        self.blocker._load_persistent_lists()
        self.blocker.load_external_blacklists(self.blocker.external_blacklist_files)

        # Assert that the detector's lists were updated
        self.mock_detector_instance.trusted_domains.update.assert_any_call(
            {"whitelisted.com", "*.trustedsubdomain.com"}
        )
        self.mock_detector_instance.blacklisted_domains.update.assert_any_call(
            {"blacklisted.com", "phishy.org"}
        )
        self.mock_detector_instance.blacklisted_domains.update.assert_any_call(
            {"externalbad.com"}
        )

        # Assert that PhishingBlocker's own blocked_domains is updated from user_blacklist
        self.assertIn("blacklisted.com", self.blocker.blocked_domains)
        self.assertIn("phishy.org", self.blocker.blocked_domains)

    async def test_initialization_schedules_background_tasks(self):
        # Test that background tasks are created.
        # In setUp, PhishingBlocker is initialized, which should start these tasks.
        # We need to check if asyncio.create_task was called for them.
        # This is tricky because they are started in __init__.
        # We can check if the task attributes on self.blocker are not None.
        self.assertIsNotNone(self.blocker.result_processor_task)
        self.assertFalse(self.blocker.result_processor_task.done())  # Should be running

        self.assertIsNotNone(self.blocker.stats_update_task)
        self.assertFalse(self.blocker.stats_update_task.done())  # Should be running

        # Ensure they are cancelled during teardown by stop()
        await self.blocker.stop()  # This should cancel them

        # After stop, tasks should be done (cancelled)
        # Give a moment for tasks to process cancellation
        await asyncio.sleep(0.01)
        self.assertTrue(self.blocker.result_processor_task.done())
        self.assertTrue(self.blocker.stats_update_task.done())

    # --- process_http_activity and submit_http_for_analysis Tests ---

    async def test_submit_http_for_analysis_schedules_task(self):
        http_data = {"host": "example.com", "path": "/", "source_ip": "1.2.3.4"}
        self.blocker.submit_http_for_analysis(http_data)
        self.mock_sio_client.start_background_task.assert_called_once_with(
            self.blocker.process_http_activity, http_data
        )

    @patch("app.services.detection.phishing_blocker.PhishingResult")
    async def test_process_http_activity_phishing_url_detected(
        self, MockPhishingResult
    ):
        # Mock detector's analyze_url to return a phishing result
        mock_phishing_result_instance = MockPhishingResult.return_value
        mock_phishing_result_instance.is_phishing = True
        mock_phishing_result_instance.url = "http://phishy.com/login"
        mock_phishing_result_instance.risk_score = 0.9
        mock_phishing_result_instance.reasons = ["Blacklisted domain"]
        mock_phishing_result_instance.timestamp = datetime.utcnow().isoformat()
        self.mock_detector_instance.analyze_url.return_value = (
            mock_phishing_result_instance
        )

        http_data = {"host": "phishy.com", "path": "/login", "source_ip": "1.2.3.4"}

        # Directly call the async method for testing its logic
        result_action = await self.blocker.process_http_activity(http_data)

        self.assertIn("phishy.com", self.blocker.blocked_domains)
        self.mock_sio_client.emit.assert_any_call("phishing_alert", unittest.mock.ANY)
        self.mock_sio_client.emit.assert_any_call("resource_blocked", unittest.mock.ANY)

        # Check the structure of the phishing_alert emission
        # Get all calls to sio.emit, then find the one for 'phishing_alert'
        phishing_alert_call = next(
            call
            for call in self.mock_sio_client.emit.call_args_list
            if call[0][0] == "phishing_alert"
        )
        alert_data = phishing_alert_call[0][1]  # Second argument of the call
        self.assertEqual(alert_data["url"], "http://phishy.com/login")
        self.assertTrue(alert_data["is_phishing"])
        self.assertIn("Blacklisted domain", alert_data["reasons"])
        self.assertEqual(result_action["action"], "blocked")

    @patch("app.services.detection.phishing_blocker.PhishingResult")
    async def test_process_http_activity_non_phishing_url(self, MockPhishingResult):
        mock_benign_result_instance = MockPhishingResult.return_value
        mock_benign_result_instance.is_phishing = False
        mock_benign_result_instance.url = "http://safe.com/"
        mock_benign_result_instance.risk_score = 0.1
        mock_benign_result_instance.reasons = []
        mock_benign_result_instance.timestamp = datetime.utcnow().isoformat()
        self.mock_detector_instance.analyze_url.return_value = (
            mock_benign_result_instance
        )

        http_data = {"host": "safe.com", "path": "/", "source_ip": "1.2.3.5"}
        initial_blocked_domains_count = len(self.blocker.blocked_domains)

        result_action = await self.blocker.process_http_activity(http_data)

        self.assertEqual(
            len(self.blocker.blocked_domains), initial_blocked_domains_count
        )
        # Check that block-related events were NOT emitted for this specific non-phishing case
        for call_args in self.mock_sio_client.emit.call_args_list:
            self.assertNotEqual(call_args[0][0], "resource_blocked")
            # Could also check that phishing_alert is not for blocking, or not sent if score is very low
        self.assertEqual(result_action["action"], "allowed")

    async def test_process_http_activity_previously_blocked_url(self):
        blocked_domain = "alreadyblocked.com"
        self.blocker.blocked_domains.add(blocked_domain)
        http_data = {"host": blocked_domain, "path": "/", "source_ip": "1.2.3.6"}

        result_action = await self.blocker.process_http_activity(http_data)

        self.mock_detector_instance.analyze_url.assert_not_called()  # Should not analyze if already blocked
        self.mock_sio_client.emit.assert_any_call("resource_blocked", unittest.mock.ANY)
        self.assertEqual(result_action["action"], "blocked")
        self.assertEqual(result_action["reason"], "previously_blocked_by_blocker")

    async def test_process_http_activity_html_fetching(self):
        # Mock detector to return non-phishing to focus on HTML fetch part
        self.mock_detector_instance.analyze_url.return_value = PhishingResult(
            url="http://fetchtest.com/",
            is_phishing=False,
            risk_score=0.1,
            reasons=[],
            timestamp=datetime.utcnow().isoformat(),
        )

        # Mock aiohttp response
        mock_response = AsyncMock(spec=aiohttp.ClientResponse)
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = AsyncMock(return_value="<html><title>Test</title></html>")
        self.mock_http_session.get.return_value.__aenter__.return_value = (
            mock_response  # For async with context
        )

        http_data = {
            "host": "fetchtest.com",
            "path": "/",
            "source_ip": "1.2.3.7",
            "headers": {"Content-Type": "text/html"},
        }

        await self.blocker.process_http_activity(http_data)

        self.mock_http_session.get.assert_called_once_with(
            "http://fetchtest.com/", timeout=unittest.mock.ANY
        )
        self.mock_detector_instance.analyze_url.assert_called_once_with(
            "http://fetchtest.com/", html_content="<html><title>Test</title></html>"
        )

    async def test_process_http_activity_html_fetching_error(self):
        self.mock_detector_instance.analyze_url.return_value = PhishingResult(
            url="http://fetcherror.com/",
            is_phishing=False,
            risk_score=0.1,
            reasons=[],
            timestamp=datetime.utcnow().isoformat(),
        )
        self.mock_http_session.get.side_effect = aiohttp.ClientError("Fetch failed")

        http_data = {
            "host": "fetcherror.com",
            "path": "/",
            "source_ip": "1.2.3.8",
            "headers": {"Content-Type": "text/html"},
        }
        await self.blocker.process_http_activity(http_data)

        self.mock_http_session.get.assert_called_once()
        # Ensure analyze_url is still called, but html_content will be None
        self.mock_detector_instance.analyze_url.assert_called_once_with(
            "http://fetcherror.com/", html_content=None
        )

    # --- process_detection_results Tests ---
    async def test_process_detection_results_handles_phishing(self):
        # This tests the task that reads from detector's internal queue
        phishing_alert_from_queue = {
            "url": "http://queuedphishing.com/bad",
            "is_phishing": True,  # Assuming the queue item indicates phishing
            "risk_score": 0.95,
            "reasons": ["From Detector Queue"],
            "timestamp": datetime.utcnow().isoformat(),
        }
        # Put a mock result onto the detector's queue
        await self.mock_detector_instance.result_queue.put(phishing_alert_from_queue)

        # Allow process_detection_results task to run. It has a sleep(0.1)
        await asyncio.sleep(0.2)

        self.assertIn("queuedphishing.com", self.blocker.blocked_domains)
        self.mock_sio_client.emit.assert_any_call("phishing_alert", unittest.mock.ANY)
        self.mock_sio_client.emit.assert_any_call("resource_blocked", unittest.mock.ANY)

    # --- Whitelist/Blacklist Socket.IO Handler Tests ---
    async def test_handle_add_to_whitelist(self):
        domain_to_whitelist = "examplewhitelist.com"
        # Pre-add to blacklist to test removal
        self.blocker.detector.blacklisted_domains.add(domain_to_whitelist)
        self.blocker.blocked_domains.add(domain_to_whitelist)

        self.mock_os_path_exists.return_value = True  # Assume files exist

        await self.blocker.handle_add_to_whitelist({"domain": domain_to_whitelist})

        self.assertIn(domain_to_whitelist, self.blocker.detector.trusted_domains)
        self.assertNotIn(domain_to_whitelist, self.blocker.detector.blacklisted_domains)
        self.assertNotIn(domain_to_whitelist, self.blocker.blocked_domains)
        self.mock_open_func.assert_any_call(self.blocker.user_whitelist_file, "w")
        self.mock_sio_client.emit.assert_called_with(
            "whitelist_updated", unittest.mock.ANY
        )

    async def test_handle_add_to_blacklist(self):
        domain_to_blacklist = "exampleblacklist.com"
        self.mock_os_path_exists.return_value = True

        await self.blocker.handle_add_to_blacklist({"domain": domain_to_blacklist})

        self.assertIn(domain_to_blacklist, self.blocker.detector.blacklisted_domains)
        self.assertIn(domain_to_blacklist, self.blocker.blocked_domains)
        self.mock_open_func.assert_any_call(self.blocker.user_blacklist_file, "w")
        self.mock_sio_client.emit.assert_called_with(
            "blacklist_updated", unittest.mock.ANY
        )

    # --- Stats Update Tests ---
    async def test_phishing_stats_update_emits_correct_data(self):
        # Manually set some counters
        self.blocker.urls_scanned_since_last_update = 10
        self.blocker.phishing_detected_since_last_update = 2
        self.blocker.detector.trusted_domains.add("trusted1.com")
        self.blocker.detector.blacklisted_domains.add("blacklisted1.com")
        self.blocker.blocked_domains.add("blocked1.com")

        await self.blocker.phishing_stats_update()  # Call directly to test emission logic

        self.mock_sio_client.emit.assert_called_once()
        args, _ = self.mock_sio_client.emit.call_args
        self.assertEqual(args[0], "phishing_stats_update")
        stats = args[1]
        self.assertEqual(stats["urls_scanned_in_period"], 10)
        self.assertEqual(stats["phishing_detected_in_period"], 2)
        self.assertGreaterEqual(stats["total_trusted_domains"], 1)
        self.assertGreaterEqual(stats["total_blacklisted_domains_detector"], 1)
        self.assertGreaterEqual(stats["total_blocked_domains_blocker"], 1)

        # Counters should be reset
        self.assertEqual(self.blocker.urls_scanned_since_last_update, 0)
        self.assertEqual(self.blocker.phishing_detected_since_last_update, 0)

    # --- Shutdown Test ---
    async def test_stop_method_cleans_up_resources(self):
        # Ensure tasks are running (they are started in setUp)
        self.assertFalse(self.blocker.result_processor_task.done())
        self.assertFalse(self.blocker.stats_update_task.done())

        await self.blocker.stop()

        self.assertFalse(self.blocker.running.value)
        self.mock_detector_instance.stop.assert_called_once()
        self.mock_http_session.close.assert_called_once()

        # Check tasks were cancelled (tasks become "done" when cancelled and awaited)
        await asyncio.sleep(0.01)  # Allow time for tasks to fully cancel
        self.assertTrue(self.blocker.result_processor_task.done())
        self.assertTrue(self.blocker.stats_update_task.done())


if __name__ == "__main__":
    unittest.main()
