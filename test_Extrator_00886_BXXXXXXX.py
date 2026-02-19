import pytest
import binascii
from Extrator_00886_BXXXXXXX import extract_nagra3_data

def test_extract_nagra3_data():
    # Create a payload of sufficient size (approx 2300 bytes)
    # Initialize with a sequence to make every byte unique-ish if possible,
    # but for simplicity let's use 0s and fill specific areas.
    payload = bytearray(2300)

    # Helper to write hex string to payload at offset
    def write_hex(offset, hex_str):
        b = binascii.unhexlify(hex_str)
        payload[offset:offset+len(b)] = b

    # Set expected values
    expected_descriptor = "CAFEBABE"
    write_hex(0, expected_descriptor)

    expected_nuid = "DEADBEEF"
    write_hex(4, expected_nuid)

    expected_eck0 = "00112233445566778899AABBCCDDEEFF"
    write_hex(19, expected_eck0)

    # Block 1 overlap check
    # subkey8A0010: 149:153 (4 bytes)
    # subkey8A_256: 152:280 (128 bytes)
    # Byte 152 is shared.

    # Let's set subkey8A0010 to AABBCCDD
    write_hex(149, "AABBCCDD")
    # This sets byte 152 to 0xDD.

    # Let's set subkey8A_256 bytes 153 onwards (index 1 in its block)
    # We want subkey8A_256 to start with DD...
    # Let's fill the rest with EE
    payload[153:280] = b'\xEE' * (280-153)

    expected_subkey8A0010 = "AABBCCDD"
    expected_subkey8A_256 = "DD" + "EE" * (280-153)

    # Block 2 (BB0583_1 = 280)
    # subkey9A1020: 282:285
    expected_subkey9A1020 = "123456"
    write_hex(282, expected_subkey9A1020)

    # Last block (BB0904 = 2143)
    # subkey0304: 2145:2147 (2 bytes)
    expected_subkey0304 = "9988"
    write_hex(2145, expected_subkey0304)

    # Run extraction
    data = extract_nagra3_data(bytes(payload))

    # Assertions
    assert data['DESCRIPTOR'] == expected_descriptor
    assert data['NUID'] == expected_nuid
    assert data['eCK0'] == expected_eck0

    assert data['subkey8A0010'] == expected_subkey8A0010
    assert data['subkey8A_256'] == expected_subkey8A_256

    assert data['subkey9A1020'] == expected_subkey9A1020
    assert data['subkey0304'] == expected_subkey0304

    # Verify a few others are present and have default 00 value (since we initialized with 0)
    assert data['eCK1'] == "00" * 16

def test_extract_nagra3_data_short_payload():
    # Test with payload shorter than required
    payload = bytearray(100) # Too short for most things

    # The current implementation uses slicing.
    # In Python, slicing out of bounds returns empty bytes or shorter bytes.
    # binascii.hexlify(b'') returns b''.
    # So we expect empty strings for missing data.

    data = extract_nagra3_data(bytes(payload))

    # 0:4 exists
    assert data['DESCRIPTOR'] == "00000000"

    # 2143 is way out of bounds
    assert data['subkey0304'] == ""
