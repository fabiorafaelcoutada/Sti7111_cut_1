#!/usr/bin/env python3
####################################################
#                                                  #
#            Nagra 3  Extrator de dados            #
#            Data: 08 de Junho de 2023             #
#                por The onsitbin                  #
#                                                  #
####################################################

import sys
import binascii
import textwrap
import os
import time

def extract_all_data(data):
    """Extracts all data fields from the binary data buffer."""
    if len(data) < 2284:
        raise IndexError("Insufficient data buffer")
    results = {}

    # Basic info
    results['DESCRIPTOR'] = binascii.hexlify(data[0:4]).decode('ascii').upper()
    results['NUID'] = binascii.hexlify(data[4:8]).decode('ascii').upper()
    results['NPROVIDER'] = binascii.hexlify(data[8:10]).decode('ascii').upper()
    results['PROVIDERID'] = binascii.hexlify(data[10:12]).decode('ascii').upper()
    results['ARCH'] = binascii.hexlify(data[12:14]).decode('ascii').upper()
    results['CWKEYDESC'] = binascii.hexlify(data[14:15]).decode('ascii').upper()
    results['Hextable'] = binascii.hexlify(data[18:19]).decode('ascii').upper()
    results['TLENGHT'] = binascii.hexlify(data[17:18]).decode('ascii').upper()

    results['BLOCK'] = binascii.hexlify(data[19:153]).decode('ascii').upper()

    # eCK Keys
    results['eCK0'] = binascii.hexlify(data[19:35]).decode('ascii').upper()
    results['eCK1'] = binascii.hexlify(data[35:51]).decode('ascii').upper()
    results['eCK2'] = binascii.hexlify(data[51:67]).decode('ascii').upper()
    results['eCK3'] = binascii.hexlify(data[67:83]).decode('ascii').upper()
    results['eCK4'] = binascii.hexlify(data[83:99]).decode('ascii').upper()
    results['eCK5'] = binascii.hexlify(data[99:115]).decode('ascii').upper()
    results['eCK6'] = binascii.hexlify(data[115:131]).decode('ascii').upper()
    results['eCK7'] = binascii.hexlify(data[131:147]).decode('ascii').upper()

    # BLOCK 0583
    results['block0583'] = binascii.hexlify(data[147:149]).decode('ascii').upper()
    results['subkey8A0010'] = binascii.hexlify(data[149:153]).decode('ascii').upper()
    results['subkey8A_256'] = binascii.hexlify(data[152:280]).decode('ascii').upper()

    # Blocks 9A/8A etc.
    def extract_block_9A_8A(offset):
        block = binascii.hexlify(data[offset:(offset + 2)]).decode('ascii').upper()
        subkey_header = binascii.hexlify(data[(offset + 2):(offset + 5)]).decode('ascii').upper()
        subkey_data = binascii.hexlify(data[(offset + 5):(offset + 5 + 132)]).decode('ascii').upper()
        return block, subkey_header, subkey_data

    results['B0583_1'], results['S9A1020'], results['S8A0100_1'] = extract_block_9A_8A(280)
    results['B0583_2'], results['S901020'], results['SD00100_1'] = extract_block_9A_8A(413)
    results['B0583_3'], results['S991020'], results['S990100_1'] = extract_block_9A_8A(546)
    results['B0583_4'], results['S981020'], results['S880100_1'] = extract_block_9A_8A(679)
    results['B0583_5'], results['SAA2020'], results['S8A0200_1'] = extract_block_9A_8A(812)
    results['B0583_6'], results['SA02020'], results['SD0200_1'] = extract_block_9A_8A(945)
    results['BB0583_7'], results['SA92020'], results['S990200_1'] = extract_block_9A_8A(1078)
    results['BB0583_8'], results['SA82020'], results['S880200_1'] = extract_block_9A_8A(1211)

    # BLOCK 01
    BB0323 = 1344
    results['block0323'] = binascii.hexlify(data[BB0323:(BB0323 + 2)]).decode('ascii').upper()
    results['subkey010E10'] = binascii.hexlify(data[(BB0323 + 2):(BB0323 + 5)]).decode('ascii').upper()
    results['subkey010E'] = binascii.hexlify(data[(BB0323 + 5):(BB0323 + 5 + 32)]).decode('ascii').upper()

    # BLOCK 81
    BB0622 = 1381
    results['block0622'] = binascii.hexlify(data[BB0622:(BB0622 + 2)]).decode('ascii').upper()
    results['subkey811000'] = binascii.hexlify(data[(BB0622 + 2):(BB0622 + 4)]).decode('ascii').upper()
    results['subkey8110'] = binascii.hexlify(data[(BB0622 + 4):(BB0622 + 4 + 32)]).decode('ascii').upper()

    # BLOCK 00
    BB0436 = 1417
    results['block0436'] = binascii.hexlify(data[BB0436:(BB0436 + 2)]).decode('ascii').upper()
    results['subkey000010'] = binascii.hexlify(data[(BB0436 + 2):(BB0436 + 5)]).decode('ascii').upper()
    results['subkeyXX0000'] = binascii.hexlify(data[(BB0436 + 5):(BB0436 + 5 + 51)]).decode('ascii').upper()

    # BLOCK 8A
    BB0746 = 1473
    results['block0746'] = binascii.hexlify(data[BB0746:(BB0746 + 2)]).decode('ascii').upper()
    results['subkey8A10_1'] = binascii.hexlify(data[(BB0746 + 2):(BB0746 + 4)]).decode('ascii').upper()
    results['subkeyXX8A10'] = binascii.hexlify(data[(BB0746 + 4):(BB0746 + 4 + 68)]).decode('ascii').upper()

    # BLOCK 8A (again? BB0724)
    BB0724 = 1545
    results['block0724'] = binascii.hexlify(data[BB0724:(BB0724 + 2)]).decode('ascii').upper()
    results['subkey8010'] = binascii.hexlify(data[(BB0724 + 2):(BB0724 + 4)]).decode('ascii').upper()
    results['subkeyXX8010'] = binascii.hexlify(data[(BB0724 + 4):(BB0724 + 4 + 68)]).decode('ascii').upper()

    # Blocks 0744
    def extract_block_0744(offset, size=68):
        block = binascii.hexlify(data[offset:(offset + 2)]).decode('ascii').upper()
        subkey_header = binascii.hexlify(data[(offset + 2):(offset + 4)]).decode('ascii').upper()
        subkey_data = binascii.hexlify(data[(offset + 4):(offset + 4 + size)]).decode('ascii').upper()
        return block, subkey_header, subkey_data

    results['B0744_0'], results['S9A20'], results['S8A0100_2'] = extract_block_0744(1583, 132)
    results['B0744_1'], results['S9020'], results['SD00100_2'] = extract_block_0744(1653, 68)
    results['B0744_2'], results['S9920'], results['S990100_2'] = extract_block_0744(1723, 68)
    results['B0744_3'], results['S9820'], results['S8801300'] = extract_block_0744(1793, 68)
    results['B0744_4'], results['SBA20'], results['S8A0300'] = extract_block_0744(1863, 132)
    results['B0744_5'], results['SB920'], results['S9903300'] = extract_block_0744(1933, 132)
    results['B0744_6'], results['SB820_1'], results['S980300'] = extract_block_0744(2003, 132)
    results['B0744_7'], results['SB820_2'], results['S880300'] = extract_block_0744(2073, 132)

    # LAST BLOCK
    BB0904 = 2143
    results['block0904'] = binascii.hexlify(data[BB0904:(BB0904 + 2)]).decode('ascii').upper()
    results['subkey0304'] = binascii.hexlify(data[(BB0904 + 2):(BB0904 + 4)]).decode('ascii').upper()
    results['subkey010400'] = binascii.hexlify(data[(BB0904 + 4):(BB0904 + 4 + 137)]).decode('ascii').upper()

    return results

def print_extracted_data(res):
    """Prints the extracted data in the original format."""
    print()
    print('CSCKeyDescriptor: ', res['DESCRIPTOR'], "(LEN of CWPK block)")
    print('NUID: ', res['NUID'])
    print('Max Number of Provider IDs: ', res['NPROVIDER'])
    print('Provider ID: ', res['PROVIDERID'], "; SysID ", int(res['PROVIDERID'], 16))
    print('Security Architecture: ', res['ARCH'])
    print('CW Key descriptor: ', res['CWKEYDESC'])
    print('Hex bytes: ', res['Hextable'])
    print('Storage table length: 0x%s'% res['TLENGHT'])

    print()
    for i in range(8):
        print(f'eCK{i}:', res[f'eCK{i}'])

    print()
    print("|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||")
    print()

    separator = "\n"

    print(res['block0583'])
    print(res['subkey8A0010'][:4], res['subkey8A0010'][4:6], "-----BLOCK 8A -1024-???? ")
    print(separator.join(textwrap.wrap(res['subkey8A_256'], 32)), separator)

    def print_block_9A_8A(block_name, subkey9A, subkey8A, label):
        print(block_name)
        print(subkey9A[:4], subkey9A[4:6], f"-----BLOCK {label}")
        print(subkey8A[:6], subkey8A[6:64])
        print(subkey8A[64:70], subkey8A[70:128])
        print(subkey8A[128:134], subkey8A[134:192])
        print(subkey8A[192:198], subkey8A[198:256], separator)

    print_block_9A_8A(res['B0583_1'], res['S9A1020'], res['S8A0100_1'], "9A/8A")
    print_block_9A_8A(res['B0583_2'], res['S901020'], res['SD00100_1'], "90/D0")
    print_block_9A_8A(res['B0583_3'], res['S991020'], res['S990100_1'], "99/99")
    print_block_9A_8A(res['B0583_4'], res['S981020'], res['S880100_1'], "98/88")
    print_block_9A_8A(res['B0583_5'], res['SAA2020'], res['S8A0200_1'], "AA/8A")
    print_block_9A_8A(res['B0583_6'], res['SA02020'], res['SD0200_1'], "A0/D0")
    print_block_9A_8A(res['BB0583_7'], res['SA92020'], res['S990200_1'], "A9/99")
    print_block_9A_8A(res['BB0583_8'], res['SA82020'], res['S880200_1'], "A8/88")

    # BLOCK 01
    print(res['block0323'])
    print(res['subkey010E10'][:4], res['subkey010E10'][4:6], "------BLOCK 01")
    print("    ", res['subkey010E'][:32])
    print("    ", res['subkey010E'][32:64], separator)

    # BLOCK 81
    print(res['block0622'])
    print(res['subkey811000'], "   -----BLOCK 81")
    print("    ", res['subkey8110'][:32])
    print("    ", res['subkey8110'][32:64], separator)

    # BLOCK 00
    print(res['block0436'])
    print(res['subkey000010'][:4], res['subkey000010'][4:6], "-----BLOCK 00")
    skXX00 = res['subkeyXX0000']
    print(skXX00[:2], "", skXX00[2:34])
    print(skXX00[34:36], "", skXX00[36:68])
    print(skXX00[68:70], "", skXX00[70:], separator)

    # BLOCK 8A
    print(res['block0746'])
    print(res['subkey8A10_1'], "-----BLOCK 8A")
    sk8A = res['subkeyXX8A10']
    print(sk8A[:2], "", sk8A[2:34])
    print(sk8A[34:36], "", sk8A[36:68])
    print(sk8A[68:70], "", sk8A[70:102])
    print(sk8A[102:104], "", sk8A[104:], separator)

    # BLOCK 8A (again? BB0724)
    print(res['block0724'])
    print(res['subkey8010'], "-----BLOCK 8A")
    sk80 = res['subkeyXX8010']
    print(sk80[:2], "", sk80[2:34])
    print(sk80[34:36], "", sk80[36:68], separator)

    def print_block_0744(block_name, subkey_header, subkey_data, label):
        print(block_name)
        print(subkey_header[:4], f"-----BLOCK {label} ")
        print(subkey_data[:2], subkey_data[2:8], subkey_data[8:66])
        print(subkey_data[66:68], subkey_data[68:74], subkey_data[74:132], separator)

    print_block_0744(res['B0744_0'], res['S9A20'], res['S8A0100_2'], "9A/8A")
    print_block_0744(res['B0744_1'], res['S9020'], res['SD00100_2'], "90/D0")
    print_block_0744(res['B0744_2'], res['S9920'], res['S990100_2'], "99/99")
    print_block_0744(res['B0744_3'], res['S9820'], res['S8801300'], "98/88")
    print_block_0744(res['B0744_4'], res['SBA20'], res['S8A0300'], "BA/8A")
    print_block_0744(res['B0744_5'], res['SB920'], res['S9903300'], "B0/D0")
    print_block_0744(res['B0744_6'], res['SB820_1'], res['S980300'], "B9/99")
    print_block_0744(res['B0744_7'], res['SB820_2'], res['S880300'], "B8/88")

    # LAST BLOCK
    print(res['block0904'])
    print(res['subkey0304'][:4], "-----LAST BLOCK")
    sk0104 = res['subkey010400']
    h0 = sk0104[:8]
    l0 = sk0104[8:76]
    h1 = sk0104[76:144]
    l1 = sk0104[144:]
    print(h0[:4], h0[4:], l0[:6], l0[6:10], l0[10:12], l0[12:20], l0[20:], end=" ")
    print(h1[:2], h1[2:], l1, separator)

def main():
    try:
        path_input = input("Input DIRECTORY here: ")
    except (EOFError, KeyboardInterrupt):
        return

    # define how date time will be presented
    date = time.strftime("%d.%m.%Y-%H.%M")
    print(date)

    mypath = os.path.join(os.path.expanduser(path_input + "/"))
    print("\nPath to files:\n", mypath)

    # print the dir content
    f_list = []
    try:
        for (dirpath, dirnames, filenames) in os.walk(mypath):
            f_list.extend(filenames)
            for f_name in f_list:
                print(f_name)
            break
    except Exception as e:
        print(f"Error walking directory: {e}")
        return

    if not f_list:
        print("No files found in directory.")
        return

    try:
        filename0 = input('\nInput binary(XXX.bin) file from the list above: ')
    except (EOFError, KeyboardInterrupt):
        return

    filename = os.path.join(mypath, filename0)

    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {filename} ({e})")
        sys.exit(2)

    res = extract_all_data(data)
    print_extracted_data(res)

if __name__ == "__main__":
    main()
