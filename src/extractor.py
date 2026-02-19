#!/usr/bin/env python3
import binascii
import textwrap
import argparse
import sys
import os
import json

def extract_nagra3_data(file_path):
    """
    Extracts Nagra 3 data from a binary file.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return {"error": str(e)}

    def get_hex(start, end):
        if start >= len(data):
            return ""
        # Handle cases where end > len(data) gracefully
        end = min(end, len(data))
        return binascii.hexlify(data[start:end]).decode('ascii').upper()

    result = {}

    result['DESCRIPTOR'] = get_hex(0, 4)
    result['NUID'] = get_hex(4, 8)
    result['NPROVIDER'] = get_hex(8, 10)
    result['PROVIDERID'] = get_hex(10, 12)
    result['ARCH'] = get_hex(12, 14)
    result['CWKEYDESC'] = get_hex(14, 15)
    result['TLENGHT'] = get_hex(17, 18)
    result['Hextable'] = get_hex(18, 19)

    # eCK keys
    result['eCK'] = []
    for i in range(8):
        start = 19 + (i * 16)
        end = start + 16
        result['eCK'].append(get_hex(start, end))

    blocks = []

    # Block 0583 (Special case in original)
    b1 = {}
    b1['name'] = "BLOCK 8A -1024-????"
    b1['block_id'] = get_hex(147, 149)
    b1['subkey'] = get_hex(149, 153)
    b1['payload'] = get_hex(152, 280)
    blocks.append(b1)

    # Helper for repetitive blocks type 1
    def parse_block_type_1(offset, name):
        b = {}
        b['name'] = name
        b['block_id'] = get_hex(offset, offset+2)
        b['subkey_prefix'] = get_hex(offset+2, offset+5)
        b['payload'] = get_hex(offset+5, offset+5+132)
        return b

    blocks.append(parse_block_type_1(280, "BLOCK 9A/8A"))
    blocks.append(parse_block_type_1(413, "BLOCK 90/D0"))
    blocks.append(parse_block_type_1(546, "BLOCK 99/99"))
    blocks.append(parse_block_type_1(679, "BLOCK 98/88"))
    blocks.append(parse_block_type_1(812, "BLOCK AA/8A"))
    blocks.append(parse_block_type_1(945, "BLOCK A0/D0"))
    blocks.append(parse_block_type_1(1078, "BLOCK A9/99"))
    blocks.append(parse_block_type_1(1211, "BLOCK A8/88"))

    # Unique blocks
    b_0323 = {}
    b_0323['name'] = "BLOCK 01"
    b_0323['block_id'] = get_hex(1344, 1346)
    b_0323['subkey_prefix'] = get_hex(1346, 1349)
    b_0323['payload'] = get_hex(1349, 1349+32)
    blocks.append(b_0323)

    b_0622 = {}
    b_0622['name'] = "BLOCK 81"
    b_0622['block_id'] = get_hex(1381, 1383)
    b_0622['subkey_prefix'] = get_hex(1383, 1385)
    b_0622['payload'] = get_hex(1385, 1385+32)
    blocks.append(b_0622)

    b_0436 = {}
    b_0436['name'] = "BLOCK 00"
    b_0436['block_id'] = get_hex(1417, 1419)
    b_0436['subkey_prefix'] = get_hex(1419, 1422)
    b_0436['payload'] = get_hex(1422, 1422+51)
    blocks.append(b_0436)

    b_0746 = {}
    b_0746['name'] = "BLOCK 8A"
    b_0746['block_id'] = get_hex(1473, 1475)
    b_0746['subkey_prefix'] = get_hex(1475, 1477)
    b_0746['payload'] = get_hex(1477, 1477+68)
    blocks.append(b_0746)

    b_0724 = {}
    b_0724['name'] = "BLOCK 8A (Short)"
    b_0724['block_id'] = get_hex(1545, 1547)
    b_0724['subkey_prefix'] = get_hex(1547, 1549)
    b_0724['payload'] = get_hex(1549, 1549+68)
    blocks.append(b_0724)

    # Helper for repetitive blocks type 2
    def parse_block_type_2(offset, name, payload_len=132):
        b = {}
        b['name'] = name
        b['block_id'] = get_hex(offset, offset+2)
        b['subkey_prefix'] = get_hex(offset+2, offset+4)
        b['payload'] = get_hex(offset+4, offset+4+payload_len)
        return b

    blocks.append(parse_block_type_2(1583, "BLOCK 9A/8A"))
    blocks.append(parse_block_type_2(1653, "BLOCK 90/D0", 68))
    blocks.append(parse_block_type_2(1723, "BLOCK 99/99", 68))
    blocks.append(parse_block_type_2(1793, "BLOCK 98/88", 68))
    blocks.append(parse_block_type_2(1863, "BLOCK BA/8A", 132))
    blocks.append(parse_block_type_2(1933, "BLOCK B0/D0", 132))
    blocks.append(parse_block_type_2(2003, "BLOCK B9/99", 132))
    blocks.append(parse_block_type_2(2073, "BLOCK B8/88", 132))

    # Last block
    blocks.append(parse_block_type_2(2143, "LAST BLOCK", 137))

    result['blocks'] = blocks
    return result

def main():
    parser = argparse.ArgumentParser(description="Extract Nagra 3 Data")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found.")
        sys.exit(1)

    data = extract_nagra3_data(args.file)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        if "error" in data:
            print(f"Error: {data['error']}")
            return

        print(f"CSCKeyDescriptor: {data.get('DESCRIPTOR')} (LEN of CWPK block)")
        print(f"NUID: {data.get('NUID')}")
        print(f"Provider ID: {data.get('PROVIDERID')}")
        print(f"eCKs:")
        for i, k in enumerate(data.get('eCK', [])):
            print(f"eCK{i}: {k}")

        for b in data.get('blocks', []):
            print(f"\n{b['name']}")
            print(f"ID: {b['block_id']}")
            print(f"Subkey: {b.get('subkey', b.get('subkey_prefix'))}")
            # Format payload with textwrap for readability
            payload = b['payload']
            wrapped = textwrap.wrap(payload, 64)
            print("Payload:")
            for line in wrapped:
                print(f"  {line}")

if __name__ == "__main__":
    main()
