import pytest
import binascii
from Extrator_00886_BXXXXXXX import extract_all_data

def test_extract_eck_keys():
    """Verify that eCK0 through eCK7 are correctly extracted from their expected offsets."""
    data = bytearray(2284)

    # Expected values for eCK0-eCK7
    expected_keys = {}
    for i in range(8):
        # Create a unique 16-byte value for each key
        key_bytes = bytes([i * 16 + j for j in range(16)])
        offset = 19 + (i * 16)
        data[offset : offset + 16] = key_bytes
        expected_keys[f'eCK{i}'] = binascii.hexlify(key_bytes).decode('ascii').upper()

    results = extract_all_data(data)

    for i in range(8):
        key_name = f'eCK{i}'
        assert results[key_name] == expected_keys[key_name], f"{key_name} mismatch"

def test_extract_basic_info():
    """Verify extraction of basic fields like DESCRIPTOR, NUID, etc."""
    data = bytearray(2284)

    data[0:4] = b'\xDE\xAD\xBE\xEF' # DESCRIPTOR
    data[4:8] = b'\x12\x34\x56\x78' # NUID
    data[8:10] = b'\x01\x02'         # NPROVIDER
    data[10:12] = b'\x03\x04'        # PROVIDERID

    results = extract_all_data(data)

    assert results['DESCRIPTOR'] == 'DEADBEEF'
    assert results['NUID'] == '12345678'
    assert results['NPROVIDER'] == '0102'
    assert results['PROVIDERID'] == '0304'

def test_extract_last_block():
    """Verify extraction from the maximum identified offset (BB0904)."""
    data = bytearray(2284)

    BB0904 = 2143
    val_block = b'\xAA\xBB'
    val_subkey = b'\xCC\xDD'
    val_data = bytes([k % 256 for k in range(137)])

    data[BB0904 : BB0904 + 2] = val_block
    data[BB0904 + 2 : BB0904 + 4] = val_subkey
    data[BB0904 + 4 : BB0904 + 4 + 137] = val_data

    results = extract_all_data(data)

    assert results['block0904'] == 'AABB'
    assert results['subkey0304'] == 'CCDD'
    assert results['subkey010400'] == binascii.hexlify(val_data).decode('ascii').upper()

def test_insufficient_data():
    """Verify that the function raises IndexError when provided with a short buffer."""
    data = bytearray(2283) # Less than required 2284 bytes
    with pytest.raises(IndexError):
        extract_all_data(data)
