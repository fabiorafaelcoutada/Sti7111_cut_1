import unittest
from unittest.mock import patch
from io import StringIO
import binascii
import Flash_Analyzer

class TestFlashAnalyzer(unittest.TestCase):
    def test_to_hex_str(self):
        self.assertEqual(Flash_Analyzer.to_hex_str(b'\xde\xad\xbe\xef'), 'DEADBEEF')
        self.assertEqual(Flash_Analyzer.to_hex_str(b''), '')

    def test_extract_keys_data_too_short(self):
        data = b'\x00' * 152
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()
            self.assertIn("Analyzing block at offset 0x0", output)
            self.assertIn("Data too short for extraction", output)

    def test_extract_keys_happy_path(self):
        # Create a buffer of 500 bytes to cover all branches
        # Using a sequence to have unique values for each field
        data = bytes([i % 256 for i in range(500)])

        # Expected values based on bytes([0, 1, 2, ...])
        # d[0:4] -> 00010203
        # d[4:8] -> 04050607
        # d[10:12] -> 0A0B (PROVIDERID) -> int is 2571

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()

            self.assertIn("CSCKeyDescriptor:  00010203", output)
            self.assertIn("NUID:  04050607", output)
            self.assertIn("Provider ID:  0A0B ; SysID  2571", output)
            self.assertIn("eCK0: 131415161718191A1B1C1D1E1F202122", output)

            # Subkeys Block 1
            # block0583 = d[147:149] -> 9394 (in hex)
            self.assertIn("9394", output)
            # subkey8A0010 = d[149:153] -> 95969798
            # subkey8A0010[:4] -> 9596, subkey8A0010[4:6] -> 97
            self.assertIn("9596 97 -----BLOCK 8A -1024-????", output)

            # Subkeys Block 2 (len(d) > 480 check)
            # BB0583_1 = 280
            # block0583_1 = d[280:282] -> 1819 (280%256=24, 281%256=25 -> 1819 hex)
            self.assertIn("1819", output)
            # subkey9A1020 = d[282:285] -> 1A1B1C
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
        # Exactly 153 bytes
        data = bytes([i % 256 for i in range(153)])

        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            Flash_Analyzer.extract_keys(data, 0)
            output = mock_stdout.getvalue()

            self.assertIn("CSCKeyDescriptor:  00010203", output)
            self.assertIn("eCK7: 838485868788898A8B8C8D8E8F909192", output)
            # Subkey block 1 should be attempted but block 2 should be skipped
            self.assertNotIn("-----BLOCK 9A/8A", output)

if __name__ == '__main__':
    unittest.main()
