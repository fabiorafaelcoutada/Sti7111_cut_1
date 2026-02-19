import unittest
from Extrator_00886_BXXXXXXX import extract_header

class TestHeaderExtraction(unittest.TestCase):
    def test_extract_header_happy_path(self):
        # Create a sample byte array large enough to cover all fields
        # Indices used:
        # DESCRIPTOR: 0:4
        # NUID: 4:8
        # NPROVIDER: 8:10
        # PROVIDERID: 10:12
        # ARCH: 12:14
        # CWKEYDESC: 14:15
        # TLENGHT: 17:18
        # Hextable: 18:19

        # Construct data such that we know the expected hex values
        # 00010203 04050607 0809 0A0B 0C0D 0E 0F10 11 12
        # DESCRIPTOR: 00010203
        # NUID: 04050607
        # NPROVIDER: 0809
        # PROVIDERID: 0A0B
        # ARCH: 0C0D
        # CWKEYDESC: 0E
        # TLENGHT: 11 (index 17)
        # Hextable: 12 (index 18)

        data = bytes(range(20)) # 0x00 to 0x13

        header = extract_header(data)

        self.assertEqual(header['DESCRIPTOR'], '00010203')
        self.assertEqual(header['NUID'], '04050607')
        self.assertEqual(header['NPROVIDER'], '0809')
        self.assertEqual(header['PROVIDERID'], '0A0B')
        self.assertEqual(header['ARCH'], '0C0D')
        self.assertEqual(header['CWKEYDESC'], '0E')
        self.assertEqual(header['TLENGHT'], '11')
        self.assertEqual(header['Hextable'], '12')

    def test_extract_header_short_data(self):
        # If data is too short, slices return partial or empty bytes
        # .hex() returns empty string
        data = b'\x00\x01'
        header = extract_header(data)
        # 0:4 -> 0001
        self.assertEqual(header['DESCRIPTOR'], '0001')
        # 4:8 -> empty
        self.assertEqual(header['NUID'], '')

if __name__ == '__main__':
    unittest.main()
