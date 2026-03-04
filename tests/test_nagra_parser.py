import unittest
from nagra_parser import Nagra3Parser
import binascii

class TestNagra3Parser(unittest.TestCase):
    def test_header_parsing(self):
        data = bytearray(3000)
        data[0:4] = b'\x11\x22\x33\x44' # DESCRIPTOR
        data[4:8] = b'\x55\x66\x77\x88' # NUID
        data[10:12] = b'\x12\x34'       # PROVIDERID

        parser = Nagra3Parser(data)
        header = parser.extract_header()

        self.assertEqual(header['DESCRIPTOR'], '11223344')
        self.assertEqual(header['NUID'], '55667788')
        self.assertEqual(header['PROVIDERID'], '1234')
        self.assertEqual(header['SYSID'], '4660') # 0x1234 = 4660

    def test_ecks_parsing(self):
        data = bytearray(3000)
        # eCK0 at index 19
        data[19:35] = b'\xAA' * 16
        # eCK7 at index 19 + 7*16 = 131
        data[131:147] = b'\xBB' * 16

        parser = Nagra3Parser(data)
        ecks = parser.extract_ecks()

        self.assertEqual(ecks['eCK0'], 'AA' * 16)
        self.assertEqual(ecks['eCK7'], 'BB' * 16)
        self.assertEqual(ecks['eCK1'], '00' * 16)

    def test_block_type_a(self):
        # Type A at offset 280
        data = bytearray(3000)
        data[280:282] = b'\x05\x83' # ID
        data[282:285] = b'\x9A\x10\x20' # Subkey ID
        # 4 keys * (3+29) bytes = 4 * 32 bytes = 128 bytes
        # data[285:285+132]
        data[285:285+6] = b'\x11\x11\x11' # H_KEY0

        parser = Nagra3Parser(data)
        block = parser.extract_subkey_block(280, 'A')

        self.assertEqual(block['id'], '0583')
        self.assertEqual(block['subkey_id'], '9A1020')
        self.assertEqual(block['keys'][0]['H'], '111111')

    def test_block_type_g(self):
        # Type G at offset 147
        data = bytearray(3000)
        data[147:149] = b'\x05\x83'
        data[149:153] = b'\x8A\x00\x10\x00'
        # The subkey_id is 4 bytes at index 2:6 relative to 147, i.e., 149:153.
        # But data starts at index 5 relative to 147, i.e., 152.
        # Index 152 is shared between subkey_id and data.

        data[152:280] = b'\xCC' * 128

        parser = Nagra3Parser(data)
        block = parser.extract_subkey_block(147, 'G')

        self.assertEqual(block['id'], '0583')
        self.assertEqual(block['subkey_id'], '8A0010CC')
        # Data starts at 147 + 5 = 152
        self.assertTrue(block['data'].startswith('CCCC'))

if __name__ == '__main__':
    unittest.main()
