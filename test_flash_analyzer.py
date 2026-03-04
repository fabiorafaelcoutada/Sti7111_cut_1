import unittest
from unittest.mock import patch
from io import StringIO
import Flash_Analyzer

class TestFlashAnalyzer(unittest.TestCase):
    def test_extract_keys_data_too_short(self):
        # Empty data results in no header being extracted
        data = b''
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()
            self.assertIn("Analyzing block at offset 0x0", output)
            self.assertIn("Data too short for extraction", output)

    def test_extract_keys_happy_path(self):
        # Create a buffer of 500 bytes to cover multiple branches
        # Using a sequence to have unique values for each field
        data = bytes([i % 256 for i in range(500)])

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()

            self.assertIn("CSCKeyDescriptor:  00010203", output)
            self.assertIn("NUID:  04050607", output)
            self.assertIn("Provider ID:  0A0B ; SysID  2571", output)
            self.assertIn("eCK0: 131415161718191A1B1C1D1E1F202122", output)

            # Subkeys Block G at offset 147
            self.assertIn("9394", output)
            self.assertIn("9596 97 -----BLOCK 8A - 1024", output)

            # Subkeys Block A at offset 280
            self.assertIn("1819", output)
            self.assertIn("1A1B 1C -----BLOCK 9A/8A", output)

    def test_extract_keys_with_offset(self):
        offset = 100
        data = b'\x00' * offset + bytes([i % 256 for i in range(500)])

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, offset)
            output = mock_stdout.getvalue()

            self.assertIn(f"Analyzing block at offset 0x{offset:X}", output)
            self.assertIn("CSCKeyDescriptor:  00010203", output)

    def test_extract_keys_boundary_condition(self):
        # Exactly 153 bytes (just enough for the first subkey G to print its partial data)
        data = bytes([i % 256 for i in range(153)])

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()

            self.assertIn("CSCKeyDescriptor:  00010203", output)
            self.assertIn("eCK7: 838485868788898A8B8C8D8E8F909192", output)
            self.assertIn("9596 97 -----BLOCK 8A - 1024", output)
            self.assertNotIn("-----BLOCK 9A/8A", output)

    @patch('builtins.open')
    @patch('Flash_Analyzer.extract_keys')
    def test_scan_file_happy_path(self, mock_extract_keys, mock_open):
        from unittest.mock import mock_open as make_mock_open

        # We need a file size larger than 0xE0000 to test the second offset
        # Let's create a dummy binary with a signature
        dummy_data = bytearray(b'\x00' * 0xE0000 + b'\x00' * 100)
        # Inject SquashFS (BE) signature at offset 0x1000
        sig = b'hsqs'
        dummy_data[0x1000:0x1004] = sig

        # Use mock_open from unittest.mock and wrap it around our dummy data
        m = make_mock_open(read_data=bytes(dummy_data))
        mock_open.side_effect = m

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.scan_file("dummy.bin")
            output = mock_stdout.getvalue()

            self.assertIn("Scanning file: dummy.bin", output)
            self.assertIn(f"File size: {len(dummy_data)} bytes", output)
            self.assertIn("Found SquashFS (BE) signature at offset 0x1000", output)
            self.assertIn("[+] Attempting key extraction...", output)

            # verify extract_keys called with offsets 0x0 and 0xE0000
            self.assertEqual(mock_extract_keys.call_count, 2)
            mock_extract_keys.assert_any_call(bytes(dummy_data), 0x0)
            mock_extract_keys.assert_any_call(bytes(dummy_data), 0xE0000)

    @patch('builtins.open')
    def test_scan_file_exception(self, mock_open):
        mock_open.side_effect = Exception("Simulated read error")

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.scan_file("error.bin")
            output = mock_stdout.getvalue()

            self.assertIn("Scanning file: error.bin", output)
            self.assertIn("Error opening file: Simulated read error", output)

    @patch('builtins.open')
    def test_scan_file_not_found(self, mock_open):
        mock_open.side_effect = FileNotFoundError("[Errno 2] No such file or directory: 'missing.bin'")

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.scan_file("missing.bin")
            output = mock_stdout.getvalue()

            self.assertIn("Scanning file: missing.bin", output)
            self.assertIn("Error opening file: [Errno 2] No such file or directory: 'missing.bin'", output)

if __name__ == '__main__':
    unittest.main()
