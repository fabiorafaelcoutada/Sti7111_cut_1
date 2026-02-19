import unittest
from unittest.mock import patch, mock_open, MagicMock
import sys
import Extrator_00886_BXXXXXXX

class TestExtrator(unittest.TestCase):
    def test_read_file_content_success(self):
        filename = "test.bin"
        expected_content = b"\x00\x01\x02\x03"

        with patch("builtins.open", mock_open(read_data=expected_content)) as mock_file:
            # We also need to mock seek, as read_file_content calls f.seek(0x0, 0)
            # mock_open handles read but seek might need attention if we assert on it.
            # But default mock_open returns a MagicMock which handles seek.

            content = Extrator_00886_BXXXXXXX.read_file_content(filename)

            mock_file.assert_called_once_with(filename, "rb")
            mock_file.return_value.seek.assert_called_once_with(0x0, 0)
            self.assertEqual(content, expected_content)

    def test_read_file_content_failure(self):
        filename = "nonexistent.bin"

        # Mock open to raise IOError
        with patch("builtins.open", side_effect=IOError("File not found")):
            # Mock sys.exit to prevent test runner from exiting
            with patch("sys.exit") as mock_exit:
                # Mock print to avoid cluttering output
                with patch("builtins.print") as mock_print:
                    Extrator_00886_BXXXXXXX.read_file_content(filename)

                    mock_print.assert_called_with("Error reading file:", filename)
                    mock_exit.assert_called_once_with(2)

if __name__ == '__main__':
    unittest.main()
