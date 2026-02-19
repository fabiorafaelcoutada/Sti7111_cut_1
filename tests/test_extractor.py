import unittest
import os
import sys

# Ensure src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from extractor import extract_nagra3_data

class TestExtractor(unittest.TestCase):
    def setUp(self):
        # Create a dummy binary file with enough bytes
        self.test_file = 'test_dump.bin'
        # Size needs to be at least 2500 bytes for offsets
        with open(self.test_file, 'wb') as f:
            f.write(b'\x00' * 3000)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_extract_nagra3_data(self):
        data = extract_nagra3_data(self.test_file)
        self.assertIsInstance(data, dict)
        self.assertIn('DESCRIPTOR', data)
        self.assertIn('eCK', data)
        self.assertEqual(len(data['eCK']), 8)
        self.assertIn('blocks', data)
        self.assertGreater(len(data['blocks']), 0)

if __name__ == '__main__':
    unittest.main()
