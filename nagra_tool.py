#!/usr/bin/env python3
import argparse
import sys
import os
import json
from nagra_parser import Nagra3Parser

def print_structured(data):
    header = data['header']
    print("====================================================")
    print("  Nagra 3 Data Extraction Report")
    print("====================================================")
    print(f"CSCKeyDescriptor: {header.get('DESCRIPTOR')} (LEN of CWPK block)")
    print(f"NUID:             {header.get('NUID')}")
    print(f"Provider ID:      {header.get('PROVIDERID')} ; SysID {header.get('SYSID')}")
    print(f"Architecture:     {header.get('ARCH')}")
    print(f"CW Key descriptor: {header.get('CWKEYDESC')}")
    print(f"Table Length:     0x{header.get('TLENGHT')}")
    print("----------------------------------------------------")

    print("eCK Keys:")
    ecks = data['ecks']
    for i in range(8):
        print(f"  eCK{i}: {ecks.get(f'eCK{i}')}")
    print("----------------------------------------------------")

    print("Subkey Blocks:")
    for block in data['subkeys']:
        print(f"[{block['offset']:08X}] {block['description']} (ID: {block['id']})")
        if 'keys' in block:
            for i, k in enumerate(block['keys']):
                if isinstance(k, dict):
                    print(f"  Key {i}: H={k['H']} L={k['L']}")
                else:
                    print(f"  Key {i}: {k}")
        elif 'data' in block:
            # Wrap long data
            wrapped = "\n    ".join([block['data'][i:i+64] for i in range(0, len(block['data']), 64)])
            print(f"  Data: {wrapped}")
        print()

def scan(filepath):
    print(f"[*] Scanning {filepath} for Nagra 3 blocks...")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error: {e}")
        return

    # Look for potential headers.
    # A simple heuristic: search for common Provider IDs or NUID patterns if known.
    # For now, let's try common offsets and also look for 0x0583 block pattern.

    potential_offsets = set([0, 0xE0000])

    # Search for "0583" followed by "8A0010" which is very common
    target = b'\x05\x83\x8A\x00\x10'
    pos = 0
    while True:
        pos = data.find(target, pos)
        if pos == -1: break
        # The block 0583 is at offset 147 relative to start of data
        potential_offsets.add(pos - 147)
        pos += 1

    found = 0
    for off in sorted(potential_offsets):
        if off < 0 or off >= len(data) - 19: continue
        parser = Nagra3Parser(data, off)
        header = parser.extract_header()
        # Basic validation: Check if Provider ID is not all zeros or all FFs
        if header.get('PROVIDERID') not in ('0000', 'FFFF'):
            print(f"[+] Found potential Nagra 3 block at 0x{off:X}")
            parsed = parser.parse_all()
            print_structured(parsed)
            found += 1

    if found == 0:
        print("[-] No Nagra 3 blocks found.")

def main():
    parser = argparse.ArgumentParser(description='Nagra 3 Data Extraction Tool')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Parse command
    parse_parser = subparsers.add_parser('parse', help='Parse a binary file at a specific offset')
    parse_parser.add_argument('file', help='Binary file to parse')
    parse_parser.add_argument('--offset', type=lambda x: int(x, 0), default=0, help='Offset in file (default: 0)')
    parse_parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a file for Nagra 3 blocks')
    scan_parser.add_argument('file', help='File to scan')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'parse':
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found.")
            sys.exit(1)

        with open(args.file, 'rb') as f:
            data = f.read()

        parser_obj = Nagra3Parser(data, args.offset)
        result = parser_obj.parse_all()

        if args.format == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_structured(result)

    elif args.command == 'scan':
        scan(args.file)

if __name__ == "__main__":
    main()
