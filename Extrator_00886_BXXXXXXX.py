#!/usr/bin/env python3
# Compatibility wrapper for legacy Python 2 script
import sys
import binascii
import textwrap
import os
import time
from nagra_parser import extract_header, extract_nagra3_data, is_safe_path

def to_hex(b):
    return binascii.hexlify(b).decode('ascii').upper()

def extract_all_data(data):
    # For test_extrator.py compatibility
    if len(data) < 2284:
        raise IndexError("Insufficient data")

    result = {}
    result['DESCRIPTOR'] = to_hex(data[0:4])
    result['NUID'] = to_hex(data[4:8])
    result['NPROVIDER'] = to_hex(data[8:10])
    result['PROVIDERID'] = to_hex(data[10:12])
    result['ARCH'] = to_hex(data[12:14])
    result['CWKEYDESC'] = to_hex(data[14:15])
    result['TLENGHT'] = to_hex(data[17:18])
    result['Hextable'] = to_hex(data[18:19])

    for i in range(8):
        start = 19 + (i * 16)
        result[f'eCK{i}'] = to_hex(data[start : start + 16])

    result['block0583'] = to_hex(data[147:149])
    result['subkey8A0010'] = to_hex(data[149:153])
    result['subkey8A_256'] = to_hex(data[152:280])

    BB0583_1 = 280
    result['subkey9A1020'] = to_hex(data[(BB0583_1 + 2):(BB0583_1 + 5)])

    BB0904 = 2143
    result['block0904'] = to_hex(data[BB0904 : BB0904 + 2])
    result['subkey0304'] = to_hex(data[BB0904 + 2 : BB0904 + 4])
    result['subkey010400'] = to_hex(data[BB0904 + 4 : BB0904 + 4 + 137])

    return result

def main():
    path = ""
    while True:
        try:
            PATH = input("Input DIRECTORY here: ")
        except EOFError:
            return

        if not PATH:
            PATH = "."

        path_val = os.path.abspath(os.path.expanduser(PATH))
        if os.path.isdir(path_val):
            path = path_val
            break
        else:
            print("Invalid directory. Please try again.")

    mypath = path

    # define how date time will be presented
    date = time.strftime("%d.%m.%Y-%H.%M")
    print (date)

    # print the dir content
    f_list = []
    for (dirpath, dirnames, filenames) in os.walk(mypath):
        f_list.extend(filenames)
        if f_list:
            print("\n".join(f_list))
        break

    print("\nPath to files:\n", mypath)
    try:
        filename0 = input('\nInput binary(XXX.bin) file from the list above: ')
    except EOFError:
        return

    filename = os.path.join(mypath, filename0)

    # SECURITY FIX: Ensure the file is within the intended directory
    if not is_safe_path(filename, mypath):
        print("Security Error: Path traversal detected!")
        sys.exit(1)

    try:
        with open(filename, 'rb') as f_in:
            data = f_in.read()
    except OSError:
        print("Error reading file:", filename)
        sys.exit(2)

    DESCRIPTOR = to_hex(data[0:4])
    NUID = to_hex(data[4:8])
    NPROVIDER = to_hex(data[8:10])
    PROVIDERID = to_hex(data[10:12])
    ARCH = to_hex(data[12:14])
    CWKEYDESC = to_hex(data[14:15])
    Hextable = to_hex(data[18:19])
    TLENGHT = to_hex(data[17:18])

    eCK0 = to_hex(data[19:35])
    eCK1 = to_hex(data[35:51])
    eCK2 = to_hex(data[51:67])
    eCK3 = to_hex(data[67:83])
    eCK4 = to_hex(data[83:99])
    eCK5 = to_hex(data[99:115])
    eCK6 = to_hex(data[115:131])
    eCK7 = to_hex(data[131:147])

    print()
    print('CSCKeyDescriptor: ', DESCRIPTOR, "(LEN of CWPK block)")
    print('NUID: ', NUID)
    print('Max Number of Provider IDs: ', NPROVIDER)
    print('Provider ID: ', PROVIDERID, "; SysID ", int(PROVIDERID, 16) if PROVIDERID else 0)
    print('Security Architecture: ', ARCH)
    print('CW Key descriptor: ', CWKEYDESC)
    print('Hex bytes: ', Hextable)
    print('Storage table length: 0x%0s'% TLENGHT)

    print('eCK0:', eCK0)
    print('eCK1:', eCK1)
    print('eCK2:', eCK2)
    print('eCK3:', eCK3)
    print('eCK4:', eCK4)
    print('eCK5:', eCK5)
    print('eCK6:', eCK6)
    print('eCK7:', eCK7)

    print()
    print("|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||")
    print()

    separator = "\n"
    tab = "    "

    try:
        block0583 = to_hex(data[147:149])
        subkey8A0010 = to_hex(data[149:153])
        subkey8A_256 = to_hex(data[152:280])
        subkey8A_256a = textwrap.wrap(subkey8A_256, 32)
        print(block0583)
        print(subkey8A0010[:4], subkey8A0010[4:6], "-----BLOCK 8A -1024-???? ")
        print(separator.join(subkey8A_256a), separator)

        BB0583_1 = 280
        block0583_1 = to_hex(data[BB0583_1:(BB0583_1 + 2)])
        subkey9A1020 = to_hex(data[(BB0583_1 + 2):(BB0583_1 + 5)])
        subkey8A0100 = to_hex(data[(BB0583_1 + 5):((BB0583_1 + 5) + 132)])
        H_KEY0 = subkey8A0100[:6]
        L_KEY0 = subkey8A0100[6:64]
        H_KEY1 = subkey8A0100[64:70]
        L_KEY1 = subkey8A0100[70:128]
        H_KEY2 = subkey8A0100[128:134]
        L_KEY2 = subkey8A0100[134:192]
        H_KEY3 = subkey8A0100[192:198]
        L_KEY3 = subkey8A0100[198:256]
        print(block0583_1)
        print(subkey9A1020[:4], subkey9A1020[4:6], "-----BLOCK 9A/8A")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0583_2 = 413
        block0583_2 = to_hex(data[BB0583_2:(BB0583_2 + 2)])
        subkey901020 = to_hex(data[(BB0583_2 + 2):(BB0583_2 + 5)])
        subkeyD00100 = to_hex(data[(BB0583_2 + 5):((BB0583_2 + 5) + 132)])
        H_KEY0 = subkeyD00100[:6]
        L_KEY0 = subkeyD00100[6:64]
        H_KEY1 = subkeyD00100[64:70]
        L_KEY1 = subkeyD00100[70:128]
        H_KEY2 = subkeyD00100[128:134]
        L_KEY2 = subkeyD00100[134:192]
        H_KEY3 = subkeyD00100[192:198]
        L_KEY3 = subkeyD00100[198:256]
        print(block0583_2)
        print(subkey901020[:4], subkey901020[4:6], "-----BLOCK 90/D0")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0583_3 = 546
        block0583_3 = to_hex(data[BB0583_3:(BB0583_3 + 2)])
        subkey991020 = to_hex(data[(BB0583_3 + 2):(BB0583_3 + 5)])
        subkey990100 = to_hex(data[(BB0583_3 + 5):((BB0583_3 + 5) + 132)])
        H_KEY0 = subkey990100[:6]
        L_KEY0 = subkey990100[6:64]
        H_KEY1 = subkey990100[64:70]
        L_KEY1 = subkey990100[70:128]
        H_KEY2 = subkey990100[128:134]
        L_KEY2 = subkey990100[134:192]
        H_KEY3 = subkey990100[192:198]
        L_KEY3 = subkey990100[198:256]
        print(block0583_3)
        print(subkey991020[:4], subkey991020[4:6], "-----BLOCK 99/99")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0583_4 = 679
        block0583_4 = to_hex(data[BB0583_4:(BB0583_4 + 2)])
        subkey981020 = to_hex(data[(BB0583_4 + 2):(BB0583_4 + 5)])
        subkey880100 = to_hex(data[(BB0583_4 + 5):((BB0583_4 + 5) + 132)])
        H_KEY0 = subkey880100[:6]
        L_KEY0 = subkey880100[6:64]
        H_KEY1 = subkey880100[64:70]
        L_KEY1 = subkey880100[70:128]
        H_KEY2 = subkey880100[128:134]
        L_KEY2 = subkey880100[134:192]
        H_KEY3 = subkey880100[192:198]
        L_KEY3 = subkey880100[198:256]
        print(block0583_4)
        print(subkey981020[:4], subkey981020[4:6], "-----BLOCK 98/88")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0583_5 = 812
        block0583_5 = to_hex(data[BB0583_5:(BB0583_5 + 2)])
        subkeyAA2020 = to_hex(data[(BB0583_5 + 2):(BB0583_5 + 5)])
        subkey8A0200 = to_hex(data[(BB0583_5 + 5):((BB0583_5 + 5) + 132)])
        H_KEY0 = subkey8A0200[:6]
        L_KEY0 = subkey8A0200[6:64]
        H_KEY1 = subkey8A0200[64:70]
        L_KEY1 = subkey8A0200[70:128]
        H_KEY2 = subkey8A0200[128:134]
        L_KEY2 = subkey8A0200[134:192]
        H_KEY3 = subkey8A0200[192:198]
        L_KEY3 = subkey8A0200[198:256]
        print(block0583_5)
        print(subkeyAA2020[:4], subkeyAA2020[4:6], "-----BLOCK AA/8A")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0583_6 = 945
        block0583_6 = to_hex(data[BB0583_6:(BB0583_6 + 2)])
        subkeyA02020 = to_hex(data[(BB0583_6 + 2):(BB0583_6 + 5)])
        subkeyD00200 = to_hex(data[(BB0583_6 + 5):((BB0583_6 + 5) + 132)])
        H_KEY0 = subkeyD00200[:6]
        L_KEY0 = subkeyD00200[6:64]
        H_KEY1 = subkeyD00200[64:70]
        L_KEY1 = subkeyD00200[70:128]
        H_KEY2 = subkeyD00200[128:134]
        L_KEY2 = subkeyD00200[134:192]
        H_KEY3 = subkeyD00200[192:198]
        L_KEY3 = subkeyD00200[198:256]
        print(block0583_6)
        print(subkeyA02020[:4], subkeyA02020[4:6], "----BLOCK A0/D0")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BBBB0583_7 = 1078
        blockBB0583_7 = to_hex(data[BBBB0583_7:(BBBB0583_7 + 2)])
        subkeyA92020 = to_hex(data[(BBBB0583_7 + 2):(BBBB0583_7 + 5)])
        subkey990200 = to_hex(data[(BBBB0583_7 + 5):((BBBB0583_7 + 5) + 132)])
        H_KEY0 = subkey990200[:6]
        L_KEY0 = subkey990200[6:64]
        H_KEY1 = subkey990200[64:70]
        L_KEY1 = subkey990200[70:128]
        H_KEY2 = subkey990200[128:134]
        L_KEY2 = subkey990200[134:192]
        H_KEY3 = subkey990200[192:198]
        L_KEY3 = subkey990200[198:256]
        print(blockBB0583_7)
        print(subkeyA92020[:4], subkeyA92020[4:6], "-----BLOCK A9/99")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BBBB0583_8 = 1211
        blockBB0583_8 = to_hex(data[BBBB0583_8:(BBBB0583_8 + 2)])
        subkeyA82020 = to_hex(data[(BBBB0583_8 + 2):(BBBB0583_8 + 5)])
        subkey880200 = to_hex(data[(BBBB0583_8 + 5):((BBBB0583_8 + 5) + 132)])
        H_KEY0 = subkey880200[:6]
        L_KEY0 = subkey880200[6:64]
        H_KEY1 = subkey880200[64:70]
        L_KEY1 = subkey880200[70:128]
        H_KEY2 = subkey880200[128:134]
        L_KEY2 = subkey880200[134:192]
        H_KEY3 = subkey880200[192:198]
        L_KEY3 = subkey880200[198:256]
        print(blockBB0583_8)
        print(subkeyA82020[:4], subkeyA82020[4:6], "-----BLOCK A8/88")
        print(H_KEY0[:6], L_KEY0)
        print(H_KEY1[:6], L_KEY1)
        print(H_KEY2[:6], L_KEY2)
        print(H_KEY3[:6], L_KEY3, separator)

        BB0323 = 1344
        block0323 = to_hex(data[BB0323:(BB0323 + 2)])
        subkey010E10 = to_hex(data[(BB0323 + 2):(BB0323 + 5)])
        subkey010E = to_hex(data[(BB0323 + 5):((BB0323 + 5) + 32)])
        H_KEY0 = subkey010E[:32]
        H_KEY1 = subkey010E[32:64]
        print(block0323)
        print(subkey010E10[:4], subkey010E10[4:6], "------BLOCK 01")
        print(tab, H_KEY0)
        print(tab, H_KEY1, separator)

        BB0622 = 1381
        block0622 = to_hex(data[BB0622:(BB0622 + 2)])
        subkey811000 = to_hex(data[(BB0622 + 2):(BB0622 + 4)])
        subkey8110 = to_hex(data[(BB0622 + 4):((BB0622 + 4) + 32)])
        H_KEY0 = subkey8110[:32]
        H_KEY1 = subkey8110[32:64]
        print(block0622)
        print(subkey811000, "   -----BLOCK 81")
        print(tab, H_KEY0)
        print(tab, H_KEY1, separator)

        BB0436 = 1417
        block0436 = to_hex(data[BB0436:(BB0436 + 2)])
        subkey000010 = to_hex(data[(BB0436 + 2):(BB0436 + 5)])
        subkeyXX0000 = to_hex(data[(BB0436 + 5):((BB0436 + 5) + 51)])
        H_KEY0 = subkeyXX0000[:2]
        L_KEY0 = subkeyXX0000[2:34]
        H_KEY1 = subkeyXX0000[34:36]
        L_KEY1 = subkeyXX0000[36:68]
        H_KEY2 = subkeyXX0000[68:70]
        L_KEY2 = subkeyXX0000[70:]
        print(block0436)
        print(subkey000010[:4], subkey000010[4:6], "-----BLOCK 00")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1)
        print(H_KEY2[:2], H_KEY2[2:], L_KEY2, separator)

        BB0746 = 1473
        block0746 = to_hex(data[BB0746:(BB0746 + 2)])
        subkey8A10 = to_hex(data[(BB0746 + 2):(BB0746 + 4)])
        subkeyXX8A10 = to_hex(data[(BB0746 + 4):((BB0746 + 4) + 68)])
        H_KEY0 = subkeyXX8A10[:2]
        L_KEY0 = subkeyXX8A10[2:34]
        H_KEY1 = subkeyXX8A10[34:36]
        L_KEY1 = subkeyXX8A10[36:68]
        H_KEY2 = subkeyXX8A10[68:70]
        L_KEY2 = subkeyXX8A10[70:102]
        H_KEY3 = subkeyXX8A10[102:104]
        L_KEY3 = subkeyXX8A10[104:]
        print(block0746)
        print(subkey8A10, "-----BLOCK 8A")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1)
        print(H_KEY2[:2], H_KEY2[2:], L_KEY2)
        print(H_KEY3[:2], H_KEY3[2:], L_KEY3, separator)

        BB0724 = 1545
        block0724 = to_hex(data[BB0724:(BB0724 + 2)])
        subkey8010 = to_hex(data[(BB0724 + 2):(BB0724 + 4)])
        subkeyXX8010 = to_hex(data[(BB0724 + 4):((BB0724 + 4) + 68)])
        H_KEY0 = subkeyXX8010[:2]
        L_KEY0 = subkeyXX8010[2:34]
        H_KEY1 = subkeyXX8010[34:36]
        L_KEY1 = subkeyXX8010[36:68]
        print(block0724)
        print(subkey8010, "-----BLOCK 8A")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_0 = 1583
        block0744_0 = to_hex(data[BB0744_0:(BB0744_0 + 2)])
        subkey9A20 = to_hex(data[(BB0744_0 + 2):(BB0744_0 + 4)])
        subkey8A0100 = to_hex(data[(BB0744_0 + 4):((BB0744_0 + 4) + 132)])
        H_KEY0 = subkey8A0100[:8]
        L_KEY0 = subkey8A0100[8:66]
        H_KEY1 = subkey8A0100[66:74]
        L_KEY1 = subkey8A0100[74:132]
        print(block0744_0)
        print(subkey9A20[:4], "-----BLOCK 9A/8A ")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_1 = 1653
        block0744_1 = to_hex(data[BB0744_1:(BB0744_1 + 2)])
        subkey9020 = to_hex(data[(BB0744_1 + 2):(BB0744_1 + 4)])
        subkeyD00100 = to_hex(data[(BB0744_1 + 4):((BB0744_1 + 4) + 68)])
        H_KEY0 = subkeyD00100[:8]
        L_KEY0 = subkeyD00100[8:66]
        H_KEY1 = subkeyD00100[66:74]
        L_KEY1 = subkeyD00100[74:132]
        print(block0744_1)
        print(subkey9020[:4], "-----BLOCK 90/D0")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_2 = 1723
        block0744_2 = to_hex(data[BB0744_2:(BB0744_2 + 2)])
        subkey9920 = to_hex(data[(BB0744_2 + 2):(BB0744_2 + 4)])
        subkey990100 = to_hex(data[(BB0744_2 + 4):((BB0744_2 + 4) + 68)])
        H_KEY0 = subkey990100[:8]
        L_KEY0 = subkey990100[8:66]
        H_KEY1 = subkey990100[66:74]
        L_KEY1 = subkey990100[74:132]
        print(block0744_2)
        print(subkey9920[:4], "-----BLOCK 99/99")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_3 = 1793
        block0744_3 = to_hex(data[BB0744_3:(BB0744_3 + 2)])
        subkey9820 = to_hex(data[(BB0744_3 + 2):(BB0744_3 + 4)])
        subkey8801300 = to_hex(data[(BB0744_3 + 4):((BB0744_3 + 4) + 68)])
        H_KEY0 = subkey8801300[:8]
        L_KEY0 = subkey8801300[8:66]
        H_KEY1 = subkey8801300[66:74]
        L_KEY1 = subkey8801300[74:132]
        print(block0744_3)
        print(subkey9820[:4], "-----BLOCK 98/88")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_4 = 1863
        block0744_4 = to_hex(data[BB0744_4:(BB0744_4 + 2)])
        subkeyBA20 = to_hex(data[(BB0744_4 + 2):(BB0744_4 + 4)])
        subkey8A0300 = to_hex(data[(BB0744_4 + 4):((BB0744_4 + 4) + 132)])
        H_KEY0 = subkey8A0300[:8]
        L_KEY0 = subkey8A0300[8:66]
        H_KEY1 = subkey8A0300[66:74]
        L_KEY1 = subkey8A0300[74:132]
        print(block0744_4)
        print(subkeyBA20[:4], "-----BLOCK BA/8A")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_5 = 1933
        block0744_5 = to_hex(data[BB0744_5:(BB0744_5 + 2)])
        subkeyB920 = to_hex(data[(BB0744_5 + 2):(BB0744_5 + 4)])
        subkey9903300 = to_hex(data[(BB0744_5 + 4):((BB0744_5 + 4) + 132)])
        H_KEY0 = subkey9903300[:8]
        L_KEY0 = subkey9903300[8:66]
        H_KEY1 = subkey9903300[66:74]
        L_KEY1 = subkey9903300[74:132]
        print(block0744_5)
        print(subkeyB920[:4], "-----BLOCK B0/D0")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_6 = 2003
        block0744_6 = to_hex(data[BB0744_6:(BB0744_6 + 2)])
        subkeyB820 = to_hex(data[(BB0744_6 + 2):(BB0744_6 + 4)])
        subkey980300 = to_hex(data[(BB0744_6 + 4):((BB0744_6 + 4) + 132)])
        H_KEY0 = subkey980300[:8]
        L_KEY0 = subkey980300[8:66]
        H_KEY1 = subkey980300[66:74]
        L_KEY1 = subkey980300[74:132]
        print(block0744_6)
        print(subkeyB820[:4], "-----BLOCK B9/99")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0744_7 = 2073
        block0744_7 = to_hex(data[BB0744_7:(BB0744_7 + 2)])
        subkeyB820 = to_hex(data[(BB0744_7 + 2):(BB0744_7 + 4)])
        subkey880300 = to_hex(data[(BB0744_7 + 4):((BB0744_7 + 4) + 132)])
        H_KEY0 = subkey880300[:8]
        L_KEY0 = subkey880300[8:66]
        H_KEY1 = subkey880300[66:74]
        L_KEY1 = subkey880300[74:132]
        print(block0744_7)
        print(subkeyB820[:4], "-----BLOCK B8/88")
        print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

        BB0904 = 2143
        block0904 = to_hex(data[BB0904:(BB0904 + 2)])
        subkey0304 = to_hex(data[(BB0904 + 2):(BB0904 + 4)])
        subkey010400 = to_hex(data[(BB0904 + 4):((BB0904 + 4) + 137)])
        H_KEY0 = subkey010400[:8]
        L_KEY0 = subkey010400[8:76]
        H_KEY1 = subkey010400[76:144]
        L_KEY1 = subkey010400[144:]
        print(block0904)
        print(subkey0304[:4], "-----LAST BLOCK")
        print(H_KEY0[:4], H_KEY0[4:], L_KEY0[:6], L_KEY0[6:10], L_KEY0[10:12], L_KEY0[12:20], L_KEY0[20:], end=" ")
        print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    except IndexError:
        print("\n[!] End of data reached during parsing.")

if __name__ == "__main__":
    main()
