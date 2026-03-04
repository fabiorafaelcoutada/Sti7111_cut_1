#!/usr/bin/env python3
####################################################
#                                                  #
#            Nagra 3  Extrator de dados            #
#            Data: 08 de Junho de 2023             #
#                por The onsitbin                  #
#                                                  #
####################################################
# Python 3 compatibility wrapper for legacy script

import sys
import os
import time
from nagra_parser import Nagra3Parser

def main():
    try:
        PATH = input("Input DIRECTORY here: ")
    except EOFError:
        PATH = ""

    date = time.strftime("%d.%m.%Y-%H.%M")
    print(date)

    while True:
        path_dir = os.path.join(os.path.expanduser(PATH + "/"))
        if os.path.isdir(path_dir):
            print("\n".join(os.listdir(path_dir)))
            break
        else:
            print(f"Invalid directory. Please try again.")
            try:
                PATH = input("Input DIRECTORY here: ")
            except EOFError:
                PATH = ""

    print(f"\nPath to files:\n{path_dir}")
    try:
        filename0 = input('\nInput binary(XXX.bin) file from the list above: ')
    except EOFError:
        filename0 = ""

    filename = os.path.join(path_dir, filename0)

    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(2)

    parser = Nagra3Parser(data)
    result = parser.parse_all()
    header = result['header']
    ecks = result['ecks']

    print()
    print('CSCKeyDescriptor: ', header['DESCRIPTOR'], "(LEN of CWPK block)")
    print('NUID: ', header['NUID'])
    print('Max Number of Provider IDs: ', header['NPROVIDER'])
    print('Provider ID: ', header['PROVIDERID'], "; SysID ", header['SYSID'])
    print('Security Architecture: ', header['ARCH'])
    print('CW Key descriptor: ', header['CWKEYDESC'])
    print('Hex bytes: ', header['Hextable'])
    print('Storage table length: 0x%s'% header['TLENGHT'])

    for i in range(8):
        print(f'eCK{i}: {ecks[f"eCK{i}"]}')

    print()
    print("|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||")
    print()

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

if __name__ == "__main__":
    main()
