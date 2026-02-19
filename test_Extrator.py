
import sys
import os
import unittest
from unittest.mock import patch
from io import StringIO
import Extrator_00886_BXXXXXXX

class TestExtrator(unittest.TestCase):
    def setUp(self):
        # Create a dummy bin file for testing
        with open('test.bin', 'wb') as f:
            # Write enough bytes to satisfy the script logic (at least 2500 bytes based on max index accessed)
            # BB0904 = 2143
            f.write(b'\x00' * 3000)

    def tearDown(self):
        if os.path.exists('test.bin'):
            os.remove('test.bin')

    @patch('builtins.input', side_effect=['/nonexistent_dir_12345', '.', 'test.bin'])
    def test_directory_validation(self, mock_input):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            # Run main
            try:
                Extrator_00886_BXXXXXXX.main()
            except SystemExit as e:
                self.fail(f"Script called sys.exit({e.code})")
            except Exception as e:
                self.fail(f"Script crashed with: {e}")

            output = mock_stdout.getvalue()

            # Verify invalid directory message
            self.assertIn("Invalid directory. Please try again.", output)

            # Verify successful execution parts (e.g., printing file path)
            self.assertIn("Path to files:", output)

            # Verify some output from the file processing indicating it reached the end or key extraction
            self.assertIn("CSCKeyDescriptor:", output)
            self.assertIn("test.bin", output) # File list or processed file

if __name__ == '__main__':
    unittest.main()
