#!/usr/bin/env python3
import sys
import os
import binascii
import textwrap

def to_hex_str(b):
    return binascii.hexlify(b).decode('ascii').upper()

def extract_keys(data, offset):
    print(f"\n[+] Analyzing block at offset 0x{offset:X}...")

    if len(data) < offset + 153:
        print("[-] Data too short for extraction")
        return

    # Slice the data starting from offset
    d = data[offset:]

    DESCRIPTOR = to_hex_str(d[0:4])
    NUID = to_hex_str(d[4:8])
    NPROVIDER = to_hex_str(d[8:10])
    PROVIDERID = to_hex_str(d[10:12])
    ARCH = to_hex_str(d[12:14])
    CWKEYDESC = to_hex_str(d[14:15])
    Hextable = to_hex_str(d[18:19])
    TLENGHT = to_hex_str(d[17:18])

    BLOCK = to_hex_str(d[19:153])

    eCK0 = to_hex_str(d[19:35])
    eCK1 = to_hex_str(d[35:51])
    eCK2 = to_hex_str(d[51:67])
    eCK3 = to_hex_str(d[67:83])
    eCK4 = to_hex_str(d[83:99])
    eCK5 = to_hex_str(d[99:115])
    eCK6 = to_hex_str(d[115:131])
    eCK7 = to_hex_str(d[131:147])

    print(f'CSCKeyDescriptor:  {DESCRIPTOR} (LEN of CWPK block)')
    print(f'NUID:  {NUID}')
    print(f'Max Number of Provider IDs:  {NPROVIDER}')
    print(f'Provider ID:  {PROVIDERID} ; SysID  {format(int(PROVIDERID, 16))}')
    print(f'Security Architecture:  {ARCH}')
    print(f'CW Key descriptor:  {CWKEYDESC}')
    print(f'Hex bytes:  {Hextable}')
    print(f'Storage table length: 0x{TLENGHT}')

    print(f'eCK0: {eCK0}')
    print(f'eCK1: {eCK1}')
    print(f'eCK2: {eCK2}')
    print(f'eCK3: {eCK3}')
    print(f'eCK4: {eCK4}')
    print(f'eCK5: {eCK5}')
    print(f'eCK6: {eCK6}')
    print(f'eCK7: {eCK7}')

    print()
    print("|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||")
    print()

    separator = "\n"
    tab = "    "

    # Subkeys extraction logic (copied and adapted from Extrator)
    # Note: Using try-except for index errors in case data is truncated
    try:
        block0583 = to_hex_str(d[147:149])
        subkey8A0010 = to_hex_str(d[149:153])
        subkey8A_256 = to_hex_str(d[152:280])
        subkey8A_256a = textwrap.wrap(subkey8A_256, 32)
        print(block0583)
        print(subkey8A0010[:4], subkey8A0010[4:6], "-----BLOCK 8A -1024-???? ")
        print(separator.join(subkey8A_256a), separator)

        # ... Add other blocks if needed, but for now this demonstrates the capability
        # The original script has many blocks hardcoded by offset relative to start of file/buffer.
        # But wait, original script reads `data = f.read()` from file after seeking.
        # So `data` starts at 0 or 0xE0000.
        # And offsets are relative to `data` start.
        # e.g. `BB0583_1 = 280`. This is relative to start of `data`.
        # So passing `d` (sliced data) works.

        # Let's add a few more blocks to be thorough.
        BB0583_1 = 280
        if len(d) > BB0583_1 + 200:
            block0583_1 = to_hex_str(d[BB0583_1:(BB0583_1 + 2)])
            subkey9A1020 = to_hex_str(d[(BB0583_1 + 2):(BB0583_1 + 5)])
            subkey8A0100 = to_hex_str(d[(BB0583_1 + 5):((BB0583_1 + 5) + 132)])
            H_KEY0 = subkey8A0100[:6]
            L_KEY0 = subkey8A0100[6:64]
            # ...
            print(block0583_1)
            print(subkey9A1020[:4], subkey9A1020[4:6], "-----BLOCK 9A/8A")
            print(H_KEY0[:6], L_KEY0)
            # Shortened output for brevity in this analyzer
            print("... (more subkeys available)")

    except Exception as e:
        print(f"Error parsing subkeys: {e}")


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

    # Signatures
    sigs = {
        b'hsqs': 'SquashFS (BE)',
        b'sqsh': 'SquashFS (LE)',
        b'\x19\x85': 'JFFS2 (BE)',
        b'\x85\x19': 'JFFS2 (LE)',
        b'UBI#': 'UBI',
        b'\x27\x05\x19\x56': 'U-Boot Image (uImage)'
    }

    found_fs = []

    # Simple scan
    print("\n[+] Scanning for filesystems...")
    for offset in range(0, file_size - 4, 65536): # Scan every 64KB block to save time, or 4 bytes?
        # Filesystems usually align to blocks (64KB, 128KB).
        # Let's scan every 4 bytes but optimized.
        # Actually in python iterating byte by byte is slow.
        # Searching for byte sequence is faster.
        pass

    # Use find() for signatures
    for sig, name in sigs.items():
        off = 0
        while True:
            off = data.find(sig, off)
            if off == -1:
                break
            print(f"Found {name} signature at offset 0x{off:X}")
            found_fs.append((off, name))
            off += 1

    # Attempt extraction at known offsets
    target_offsets = [0x0, 0xE0000]

    # Add any found SquashFS offsets as potential candidates if they contain data
    # (Though keys are usually outside the FS)

    print("\n[+] Attempting key extraction...")
    for off in target_offsets:
        if off < file_size:
            extract_keys(data, off)
        else:
            print(f"Offset 0x{off:X} is beyond end of file.")

    # Also check if we can find 'CSCKeyDescriptor' string?
    # The original script OUTPUTS 'CSCKeyDescriptor'. It reads 4 bytes into DESCRIPTOR.
    # We don't know what DESCRIPTOR value is.

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <flash_dump.bin>")
        sys.exit(1)

    scan_file(sys.argv[1])
