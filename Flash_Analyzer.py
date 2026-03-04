#!/usr/bin/env python3
import sys
import os
import argparse
from nagra_parser import Nagra3Parser

def extract_keys(data, offset):
    print(f"\n[+] Analyzing block at offset 0x{offset:X}...")

    parser = Nagra3Parser(data, offset)
    result = parser.parse_all()
    header = result['header']

    if not header:
        print("[-] Data too short for extraction")
        return

    print(f"CSCKeyDescriptor:  {header['DESCRIPTOR']} (LEN of CWPK block)")
    print(f"NUID:  {header['NUID']}")
    print(f"Max Number of Provider IDs:  {header['NPROVIDER']}")
    print(f"Provider ID:  {header['PROVIDERID']} ; SysID  {header['SYSID']}")
    print(f"Security Architecture:  {header['ARCH']}")
    print(f"CW Key descriptor:  {header['CWKEYDESC']}")
    print(f"Hex bytes:  {header['Hextable']}")
    print(f"Storage table length: 0x{header['TLENGHT']}")

    ecks = result['ecks']
    for i in range(8):
        print(f"eCK{i}: {ecks[f'eCK{i}']}")

    print("\n|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||\n")

    for block in result['subkeys']:
        print(block['id'])
        print(f"{block['subkey_id'][:4]} {block['subkey_id'][4:6]} -----{block['description']}")
        if 'keys' in block:
            for k in block['keys']:
                if isinstance(k, dict):
                    print(f"{k['H']} {k['L']}")
                else:
                    print(f"    {k}")
        elif 'data' in block:
            import textwrap
            for line in textwrap.wrap(block['data'], 32):
                print(line)
        print()

def scan_file(filepath):
    print(f"Scanning file: {filepath}")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error opening file: {e}")
        return

    file_size = len(data)
    print(f"File size: {file_size} bytes")

    sigs = {
        b'hsqs': 'SquashFS (BE)',
        b'sqsh': 'SquashFS (LE)',
        b'\x19\x85': 'JFFS2 (BE)',
        b'\x85\x19': 'JFFS2 (LE)',
        b'UBI#': 'UBI',
        b'\x27\x05\x19\x56': 'U-Boot Image (uImage)'
    }

    print("\n[+] Scanning for filesystems...")
    for sig, name in sigs.items():
        off = 0
        while True:
            off = data.find(sig, off)
            if off == -1: break
            print(f"Found {name} signature at offset 0x{off:X}")
            off += 1

    target_offsets = [0x0, 0xE0000]
    print("\n[+] Attempting key extraction...")
    for off in target_offsets:
        if off < file_size:
            extract_keys(data, off)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <flash_dump.bin>")
        sys.exit(1)
    scan_file(sys.argv[1])
