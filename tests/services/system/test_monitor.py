import unittest
import os
import hashlib
import tempfile
from unittest.mock import patch, MagicMock
import logging

# Adjust the import path according to your project structure
from app.services.system.monitor import SystemMonitorProcess


class TestCalculateFileHash(unittest.TestCase):

    def setUp(self):
        # SystemMonitorProcess requires arguments for initialization,
        # but we are only testing a method. We can pass None or mocks
        # if the __init__ method of SystemMonitorProcess doesn't use them
        # immediately or if the method we're testing doesn't depend on them.
        # For _calculate_file_hash, it's a standalone utility method within the class,
        # so it doesn't rely on the instance's state being fully set up by __init__.
        self.monitor_process = SystemMonitorProcess(sio=None, data_queue=None, control_queue=None)

        # Create a temporary file for testing
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.temp_file.write(b"This is a test file.")
        self.temp_file.close()
        self.file_path = self.temp_file.name

        # Create a temporary directory for testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

        # Define a path for a non-existent file
        self.non_existent_file_path = os.path.join(self.temp_dir.name, "non_existent_file.txt")

    def tearDown(self):
        # Clean up the temporary file and directory
        os.remove(self.file_path)
        self.temp_dir.cleanup()

    def test_hash_regular_file(self):
        """Test hashing a regular, existing file."""
        expected_content = b"This is a test file."
        expected_sha256 = hashlib.sha256(expected_content).hexdigest()
        expected_md5 = hashlib.md5(expected_content).hexdigest()
        expected_size = len(expected_content)

        result = self.monitor_process._calculate_file_hash(self.file_path)

        self.assertIsNotNone(result)
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(result["md5"], expected_md5)
        self.assertEqual(result["file_size"], expected_size)
        self.assertTrue(os.path.exists(self.file_path)) # Ensure file still exists

    def test_hash_directory(self):
        """Test attempting to hash a directory."""
        with self.assertLogs(logger='SystemMonitor', level='WARNING') as cm:
            result = self.monitor_process._calculate_file_hash(self.dir_path)
        self.assertIsNone(result)
        self.assertIn(f"Skipping directory: {self.dir_path}", cm.output[0])

    def test_hash_non_existent_file(self):
        """Test attempting to hash a non-existent file."""
        with self.assertLogs(logger='SystemMonitor', level='WARNING') as cm:
            result = self.monitor_process._calculate_file_hash(self.non_existent_file_path)
        self.assertIsNone(result)
        self.assertIn(f"File not found: {self.non_existent_file_path}", cm.output[0])

    def test_hash_file_too_large(self):
        """Test attempting to hash a file that exceeds the max size."""
        # Store original value to restore it later if necessary (good practice)
        original_max_file_size = self.monitor_process._max_file_size
        self.monitor_process._max_file_size = 10 # Set max size to 10 bytes for test

        # File content is "This is a test file." (20 bytes)
        with self.assertLogs(logger='SystemMonitor', level='WARNING') as cm:
            result = self.monitor_process._calculate_file_hash(self.file_path)

        self.assertIsNone(result)
        self.assertIn(f"File too large for hashing: {self.file_path}", cm.output[0])

        # Restore original value
        self.monitor_process._max_file_size = original_max_file_size

    @patch('os.path.getsize', return_value=100) # Mock getsize to simulate file exists
    @patch('builtins.open', side_effect=PermissionError("Permission denied"))
    def test_hash_permission_error(self, mock_open, mock_getsize):
        """Test attempting to hash a file with a permission error."""
        with self.assertLogs(logger='SystemMonitor', level='WARNING') as cm:
            result = self.monitor_process._calculate_file_hash(self.file_path)
        self.assertIsNone(result)
        self.assertIn(f"Permission denied accessing {self.file_path}", cm.output[0])
        mock_open.assert_called_once_with(self.file_path, "rb")

    @patch('os.path.getsize', return_value=100) # Mock getsize to simulate file exists
    @patch('builtins.open', side_effect=OSError("Some OS error")) # Simulate generic OSError
    def test_hash_os_error(self, mock_open, mock_getsize):
        """Test attempting to hash a file with a generic OS error."""
        with self.assertLogs(logger='SystemMonitor', level='ERROR') as cm:
            result = self.monitor_process._calculate_file_hash(self.file_path)
        self.assertIsNone(result)
        self.assertIn(f"File access error: Some OS error", cm.output[0])
        mock_open.assert_called_once_with(self.file_path, "rb")

if __name__ == '__main__':
    unittest.main()
