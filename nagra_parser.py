#!/usr/bin/env python3
import binascii
import textwrap
import os

def is_safe_path(filepath, base_dir=None):
    """
    Prevents path traversal attacks by validating resolved absolute paths
    against an allowed base directory.
    """
    if base_dir is None:
        base_dir = os.getcwd()
    base_dir = os.path.abspath(base_dir)
    filepath = os.path.abspath(filepath)
    return os.path.commonpath([base_dir, filepath]) == base_dir

class Nagra3Parser:
    """
    A library for parsing Nagra 3 conditional access system data blocks.
    """

    def __init__(self, data, offset=0):
        self.data = data[offset:]
        self.offset = offset

    @staticmethod
    def to_hex(b):
        return binascii.hexlify(b).decode('ascii').upper()

    def extract_header(self):
        """Extracts the Nagra 3 header information."""
        if len(self.data) == 0:
            return {}

        provider_id = self.to_hex(self.data[10:12])
        try:
            sys_id = str(int(provider_id, 16)) if provider_id else "0"
        except ValueError:
            sys_id = "0"

        return {
            'DESCRIPTOR': self.to_hex(self.data[0:4]),
            'NUID': self.to_hex(self.data[4:8]),
            'NPROVIDER': self.to_hex(self.data[8:10]),
            'PROVIDERID': provider_id,
            'SYSID': sys_id,
            'ARCH': self.to_hex(self.data[12:14]),
            'CWKEYDESC': self.to_hex(self.data[14:15]),
            'TLENGHT': self.to_hex(self.data[17:18]),
            'Hextable': self.to_hex(self.data[18:19]),
        }

    def extract_ecks(self):
        """Extracts the 8 eCK keys."""
        ecks = {}
        for i in range(8):
            start = 19 + (i * 16)
            end = start + 16
            if len(self.data) >= end:
                ecks[f'eCK{i}'] = self.to_hex(self.data[start:end])
            else:
                ecks[f'eCK{i}'] = ""
        return ecks

    def extract_subkey_block(self, offset, block_type):
        """Extracts a subkey block based on its type and offset."""
        d = self.data[offset:]

        if block_type == 'G': # e.g. Block 0583 at 147
            if len(d) < 5: return None
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:6]),
                'data': self.to_hex(d[5:133])
            }
        elif block_type == 'A': # e.g. BB0583_1 at 280
            if len(d) < 5: return None
            block_id = self.to_hex(d[0:2])
            subkey_id = self.to_hex(d[2:5])
            raw_data = self.to_hex(d[5:137])
            return {
                'id': block_id,
                'subkey_id': subkey_id,
                'keys': [
                    {'H': raw_data[0:6], 'L': raw_data[6:64]},
                    {'H': raw_data[64:70], 'L': raw_data[70:128]},
                    {'H': raw_data[128:134], 'L': raw_data[134:192]},
                    {'H': raw_data[192:198], 'L': raw_data[198:256]}
                ]
            }
        elif block_type == 'B': # e.g. BB0323 at 1344
            if len(d) < 5: return None
            raw_data = self.to_hex(d[5:37])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:5]),
                'keys': [raw_data[0:32], raw_data[32:64]]
            }
        elif block_type == 'C': # e.g. BB0622 at 1381
            if len(d) < 4: return None
            raw_data = self.to_hex(d[4:36])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:4]),
                'keys': [raw_data[0:32], raw_data[32:64]]
            }
        elif block_type == 'D': # e.g. BB0436 at 1417
            if len(d) < 5: return None
            raw_data = self.to_hex(d[5:56])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:5]),
                'keys': [
                    {'H': raw_data[0:2], 'L': raw_data[2:34]},
                    {'H': raw_data[34:36], 'L': raw_data[36:68]},
                    {'H': raw_data[68:70], 'L': raw_data[70:102]}
                ]
            }
        elif block_type == 'E': # e.g. BB0746 at 1473
            if len(d) < 4: return None
            raw_data = self.to_hex(d[4:72])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:4]),
                'keys': [
                    {'H': raw_data[0:2], 'L': raw_data[2:34]},
                    {'H': raw_data[34:36], 'L': raw_data[36:68]},
                    {'H': raw_data[68:70], 'L': raw_data[70:102]},
                    {'H': raw_data[102:104], 'L': raw_data[104:136]}
                ]
            }
        elif block_type == 'F': # e.g. BB0724 at 1545
            if len(d) < 4: return None
            raw_data = self.to_hex(d[4:38])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:4]),
                'keys': [
                    {'H': raw_data[0:2], 'L': raw_data[2:34]},
                    {'H': raw_data[34:36], 'L': raw_data[36:68]}
                ]
            }
        elif block_type == 'H': # e.g. BB0744_0 at 1583
            if len(d) < 4: return None
            raw_data = self.to_hex(d[4:70])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:4]),
                'keys': [
                    {'H': raw_data[0:8], 'L': raw_data[8:66]},
                    {'H': raw_data[66:74], 'L': raw_data[74:132]}
                ]
            }
        elif block_type == 'I': # e.g. BB0904 at 2143
            if len(d) < 4: return None
            raw_data = self.to_hex(d[4:141])
            return {
                'id': self.to_hex(d[0:2]),
                'subkey_id': self.to_hex(d[2:4]),
                'keys': [
                    {'H': raw_data[0:8], 'L': raw_data[8:76]},
                    {'H': raw_data[76:144], 'L': raw_data[144:274]}
                ]
            }
        return None

    def parse_all(self):
        """Parses all known data blocks and returns a structured dictionary."""
        result = {
            'header': self.extract_header(),
            'ecks': self.extract_ecks(),
            'subkeys': []
        }

        offsets = [
            (147, 'G', "BLOCK 8A - 1024"),
            (280, 'A', "BLOCK 9A/8A"),
            (413, 'A', "BLOCK 90/D0"),
            (546, 'A', "BLOCK 99/99"),
            (679, 'A', "BLOCK 98/88"),
            (812, 'A', "BLOCK AA/8A"),
            (945, 'A', "BLOCK A0/D0"),
            (1078, 'A', "BLOCK A9/99"),
            (1211, 'A', "BLOCK A8/88"),
            (1344, 'B', "BLOCK 01"),
            (1381, 'C', "BLOCK 81"),
            (1417, 'D', "BLOCK 00"),
            (1473, 'E', "BLOCK 8A"),
            (1545, 'F', "BLOCK 8A"),
            (1583, 'H', "BLOCK 9A/8A"),
            (1653, 'H', "BLOCK 90/D0"),
            (1723, 'H', "BLOCK 99/99"),
            (1793, 'H', "BLOCK 98/88"),
            (1863, 'H', "BLOCK BA/8A"),
            (1933, 'H', "BLOCK B0/D0"),
            (2003, 'H', "BLOCK B9/99"),
            (2073, 'H', "BLOCK B8/88"),
            (2143, 'I', "LAST BLOCK"),
        ]

        for off, btype, desc in offsets:
            block = self.extract_subkey_block(off, btype)
            if block:
                block['description'] = desc
                block['offset'] = self.offset + off
                result['subkeys'].append(block)

        return result

def extract_header(data):
    """Compatibility function for existing tests."""
    parser = Nagra3Parser(data)
    return parser.extract_header()

def extract_nagra3_data(data):
    """Compatibility function for existing tests."""
    parser = Nagra3Parser(data)
    header = parser.extract_header()
    ecks = parser.extract_ecks()

    result = {}
    result.update(header)
    result.update(ecks)

    block_g = parser.extract_subkey_block(147, 'G')
    if block_g:
        result['block0583'] = block_g['id']
        result['subkey8A0010'] = block_g['subkey_id']
        result['subkey8A_256'] = block_g['data']

    block_a = parser.extract_subkey_block(280, 'A')
    if block_a:
        result['subkey9A1020'] = block_a['subkey_id']

    block_i = parser.extract_subkey_block(2143, 'I')
    if block_i:
        result['subkey0304'] = block_i['subkey_id']
    else:
        result['subkey0304'] = ""

    return result
