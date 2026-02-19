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
from os import path
from os import walk
import time

def extract_nagra3_data(data):
    """
    Extracts Nagra 3 data from the provided binary data.
    Returns a dictionary containing all extracted fields.
    """
    extracted = {}

    # Helper for consistent hex conversion
    def to_hex(b):
        return binascii.hexlify(b).decode('ascii').upper()

    extracted['DESCRIPTOR'] = to_hex(data[0:4])
    extracted['NUID'] = to_hex(data[4:8])
    extracted['NPROVIDER'] = to_hex(data[8:10])
    extracted['PROVIDERID'] = to_hex(data[10:12])
    extracted['ARCH'] = to_hex(data[12:14])
    extracted['CWKEYDESC'] = to_hex(data[14:15])
    extracted['Hextable'] = to_hex(data[18:19])
    extracted['TLENGHT'] = to_hex(data[17:18])

    extracted['BLOCK'] = to_hex(data[19:153])

    extracted['eCK0'] = to_hex(data[19:35])
    extracted['eCK1'] = to_hex(data[35:51])
    extracted['eCK2'] = to_hex(data[51:67])
    extracted['eCK3'] = to_hex(data[67:83])
    extracted['eCK4'] = to_hex(data[83:99])
    extracted['eCK5'] = to_hex(data[99:115])
    extracted['eCK6'] = to_hex(data[115:131])
    extracted['eCK7'] = to_hex(data[131:147])

    # Block 1
    extracted['block0583'] = to_hex(data[147:149])
    extracted['subkey8A0010'] = to_hex(data[149:153])
    extracted['subkey8A_256'] = to_hex(data[152:280])

    # Block 2 (BB0583_1)
    BB0583_1 = 280
    extracted['BB0583_1'] = BB0583_1
    extracted['block0583_1'] = to_hex(data[BB0583_1:(BB0583_1 + 2)])
    extracted['subkey9A1020'] = to_hex(data[(BB0583_1 + 2):(BB0583_1 + 5)])
    extracted['subkey8A0100'] = to_hex(data[(BB0583_1 + 5):((BB0583_1 + 5) + 132)])

    # Block 3 (BB0583_2)
    BB0583_2 = 413
    extracted['BB0583_2'] = BB0583_2
    extracted['block0583_2'] = to_hex(data[BB0583_2:(BB0583_2 + 2)])
    extracted['subkey901020'] = to_hex(data[(BB0583_2 + 2):(BB0583_2 + 5)])
    extracted['subkeyD00100'] = to_hex(data[(BB0583_2 + 5):((BB0583_2 + 5) + 132)])

    # Block 4 (BB0583_3)
    BB0583_3 = 546
    extracted['BB0583_3'] = BB0583_3
    extracted['block0583_3'] = to_hex(data[BB0583_3:(BB0583_3 + 2)])
    extracted['subkey991020'] = to_hex(data[(BB0583_3 + 2):(BB0583_3 + 5)])
    extracted['subkey990100'] = to_hex(data[(BB0583_3 + 5):((BB0583_3 + 5) + 132)])

    # Block 5 (BB0583_4)
    BB0583_4 = 679
    extracted['BB0583_4'] = BB0583_4
    extracted['block0583_4'] = to_hex(data[BB0583_4:(BB0583_4 + 2)])
    extracted['subkey981020'] = to_hex(data[(BB0583_4 + 2):(BB0583_4 + 5)])
    extracted['subkey880100'] = to_hex(data[(BB0583_4 + 5):((BB0583_4 + 5) + 132)])

    # Block 6 (BB0583_5)
    BB0583_5 = 812
    extracted['BB0583_5'] = BB0583_5
    extracted['block0583_5'] = to_hex(data[BB0583_5:(BB0583_5 + 2)])
    extracted['subkeyAA2020'] = to_hex(data[(BB0583_5 + 2):(BB0583_5 + 5)])
    extracted['subkey8A0200'] = to_hex(data[(BB0583_5 + 5):((BB0583_5 + 5) + 132)])

    # Block 7 (BB0583_6)
    BB0583_6 = 945
    extracted['BB0583_6'] = BB0583_6
    extracted['block0583_6'] = to_hex(data[BB0583_6:(BB0583_6 + 2)])
    extracted['subkeyA02020'] = to_hex(data[(BB0583_6 + 2):(BB0583_6 + 5)])
    extracted['subkeyD00200'] = to_hex(data[(BB0583_6 + 5):((BB0583_6 + 5) + 132)])

    # Block 8 (BBBB0583_7)
    BBBB0583_7 = 1078
    extracted['BBBB0583_7'] = BBBB0583_7
    extracted['blockBB0583_7'] = to_hex(data[BBBB0583_7:(BBBB0583_7 + 2)])
    extracted['subkeyA92020'] = to_hex(data[(BBBB0583_7 + 2):(BBBB0583_7 + 5)])
    extracted['subkey990200'] = to_hex(data[(BBBB0583_7 + 5):((BBBB0583_7 + 5) + 132)])

    # Block 9 (BBBB0583_8)
    BBBB0583_8 = 1211
    extracted['BBBB0583_8'] = BBBB0583_8
    extracted['blockBB0583_8'] = to_hex(data[BBBB0583_8:(BBBB0583_8 + 2)])
    extracted['subkeyA82020'] = to_hex(data[(BBBB0583_8 + 2):(BBBB0583_8 + 5)])
    extracted['subkey880200'] = to_hex(data[(BBBB0583_8 + 5):((BBBB0583_8 + 5) + 132)])

    # Block 10 (BB0323)
    BB0323 = 1344
    extracted['BB0323'] = BB0323
    extracted['block0323'] = to_hex(data[BB0323:(BB0323 + 2)])
    extracted['subkey010E10'] = to_hex(data[(BB0323 + 2):(BB0323 + 5)])
    extracted['subkey010E'] = to_hex(data[(BB0323 + 5):((BB0323 + 5) + 32)])

    # Block 11 (BB0622)
    BB0622 = 1381
    extracted['BB0622'] = BB0622
    extracted['block0622'] = to_hex(data[BB0622:(BB0622 + 2)])
    extracted['subkey811000'] = to_hex(data[(BB0622 + 2):(BB0622 + 4)])
    extracted['subkey8110'] = to_hex(data[(BB0622 + 4):((BB0622 + 4) + 32)])

    # Block 12 (BB0436)
    BB0436 = 1417
    extracted['BB0436'] = BB0436
    extracted['block0436'] = to_hex(data[BB0436:(BB0436 + 2)])
    extracted['subkey000010'] = to_hex(data[(BB0436 + 2):(BB0436 + 5)])
    extracted['subkeyXX0000'] = to_hex(data[(BB0436 + 5):((BB0436 + 5) + 51)])

    # Block 13 (BB0746)
    BB0746 = 1473
    extracted['BB0746'] = BB0746
    extracted['block0746'] = to_hex(data[BB0746:(BB0746 + 2)])
    extracted['subkey8A10'] = to_hex(data[(BB0746 + 2):(BB0746 + 4)])
    extracted['subkeyXX8A10'] = to_hex(data[(BB0746 + 4):((BB0746 + 4) + 68)])

    # Block 14 (BB0724)
    BB0724 = 1545
    extracted['BB0724'] = BB0724
    extracted['block0724'] = to_hex(data[BB0724:(BB0724 + 2)])
    extracted['subkey8010'] = to_hex(data[(BB0724 + 2):(BB0724 + 4)])
    extracted['subkeyXX8010'] = to_hex(data[(BB0724 + 4):((BB0724 + 4) + 68)])

    # Block 15 (BB0744_0)
    BB0744_0 = 1583
    extracted['BB0744_0'] = BB0744_0
    extracted['block0744_0'] = to_hex(data[BB0744_0:(BB0744_0 + 2)])
    extracted['subkey9A20'] = to_hex(data[(BB0744_0 + 2):(BB0744_0 + 4)])
    extracted['subkey8A0100_2'] = to_hex(data[(BB0744_0 + 4):((BB0744_0 + 4) + 132)])

    # Block 16 (BB0744_1)
    BB0744_1 = 1653
    extracted['BB0744_1'] = BB0744_1
    extracted['block0744_1'] = to_hex(data[BB0744_1:(BB0744_1 + 2)])
    extracted['subkey9020'] = to_hex(data[(BB0744_1 + 2):(BB0744_1 + 4)])
    extracted['subkeyD00100_2'] = to_hex(data[(BB0744_1 + 4):((BB0744_1 + 4) + 68)])

    # Block 17 (BB0744_2)
    BB0744_2 = 1723
    extracted['BB0744_2'] = BB0744_2
    extracted['block0744_2'] = to_hex(data[BB0744_2:(BB0744_2 + 2)])
    extracted['subkey9920'] = to_hex(data[(BB0744_2 + 2):(BB0744_2 + 4)])
    extracted['subkey990100_2'] = to_hex(data[(BB0744_2 + 4):((BB0744_2 + 4) + 68)])

    # Block 18 (BB0744_3)
    BB0744_3 = 1793
    extracted['BB0744_3'] = BB0744_3
    extracted['block0744_3'] = to_hex(data[BB0744_3:(BB0744_3 + 2)])
    extracted['subkey9820'] = to_hex(data[(BB0744_3 + 2):(BB0744_3 + 4)])
    extracted['subkey8801300'] = to_hex(data[(BB0744_3 + 4):((BB0744_3 + 4) + 68)])

    # Block 19 (BB0744_4)
    BB0744_4 = 1863
    extracted['BB0744_4'] = BB0744_4
    extracted['block0744_4'] = to_hex(data[BB0744_4:(BB0744_4 + 2)])
    extracted['subkeyBA20'] = to_hex(data[(BB0744_4 + 2):(BB0744_4 + 4)])
    extracted['subkey8A0300'] = to_hex(data[(BB0744_4 + 4):((BB0744_4 + 4) + 132)])

    # Block 20 (BB0744_5)
    BB0744_5 = 1933
    extracted['BB0744_5'] = BB0744_5
    extracted['block0744_5'] = to_hex(data[BB0744_5:(BB0744_5 + 2)])
    extracted['subkeyB920'] = to_hex(data[(BB0744_5 + 2):(BB0744_5 + 4)])
    extracted['subkey9903300'] = to_hex(data[(BB0744_5 + 4):((BB0744_5 + 4) + 132)])

    # Block 21 (BB0744_6)
    BB0744_6 = 2003
    extracted['BB0744_6'] = BB0744_6
    extracted['block0744_6'] = to_hex(data[BB0744_6:(BB0744_6 + 2)])
    extracted['subkeyB820'] = to_hex(data[(BB0744_6 + 2):(BB0744_6 + 4)])
    extracted['subkey980300'] = to_hex(data[(BB0744_6 + 4):((BB0744_6 + 4) + 132)])

    # Block 22 (BB0744_7)
    BB0744_7 = 2073
    extracted['BB0744_7'] = BB0744_7
    extracted['block0744_7'] = to_hex(data[BB0744_7:(BB0744_7 + 2)])
    extracted['subkeyB820_2'] = to_hex(data[(BB0744_7 + 2):(BB0744_7 + 4)])
    extracted['subkey880300'] = to_hex(data[(BB0744_7 + 4):((BB0744_7 + 4) + 132)])

    # Block 23 (BB0904)
    BB0904 = 2143
    extracted['BB0904'] = BB0904
    extracted['block0904'] = to_hex(data[BB0904:(BB0904 + 2)])
    extracted['subkey0304'] = to_hex(data[(BB0904 + 2):(BB0904 + 4)])
    extracted['subkey010400'] = to_hex(data[(BB0904 + 4):((BB0904 + 4) + 137)])

    return extracted

def print_nagra3_data(data):
    """
    Prints the extracted Nagra 3 data.
    """
    print()
    print('CSCKeyDescriptor: ', data['DESCRIPTOR'], "(LEN of CWPK block)")
    print('NUID: ', data['NUID'])
    print('Max Number of Provider IDs: ', data['NPROVIDER'])
    print('Provider ID: ', data['PROVIDERID'], "; SysID ", format(int(data['PROVIDERID'], 16)))
    print('Security Architecture: ', data['ARCH'])
    print('CW Key descriptor: ', data['CWKEYDESC'])
    print('Hex bytes: ', data['Hextable'])
    print('Storage table length: 0x%0s' % data['TLENGHT'])

    print('eCK0:', data['eCK0'])
    print('eCK1:', data['eCK1'])
    print('eCK2:', data['eCK2'])
    print('eCK3:', data['eCK3'])
    print('eCK4:', data['eCK4'])
    print('eCK5:', data['eCK5'])
    print('eCK6:', data['eCK6'])
    print('eCK7:', data['eCK7'])

    print()
    print("|||||||||||||||||||||||||||||||||||||")
    print("|| New datakeys protection level  || ")
    print("|||||||||||||||||||||||||||||||||||||")
    print()

    separator = "\n"
    tab = "    "

    # Block 1
    subkey8A_256a = textwrap.wrap(data['subkey8A_256'], 32)
    print(data['block0583'])
    print(data['subkey8A0010'][:4], data['subkey8A0010'][4:6], "-----BLOCK 8A -1024-???? ")
    print(separator.join(subkey8A_256a), separator)

    # Block 2
    subkey8A0100a = textwrap.wrap(data['subkey8A0100'], 132)
    H_KEY0 = data['subkey8A0100'][:6]
    L_KEY0 = data['subkey8A0100'][6:64]
    H_KEY1 = data['subkey8A0100'][64:70]
    L_KEY1 = data['subkey8A0100'][70:128]
    H_KEY2 = data['subkey8A0100'][128:134]
    L_KEY2 = data['subkey8A0100'][134:192]
    H_KEY3 = data['subkey8A0100'][192:198]
    L_KEY3 = data['subkey8A0100'][198:256]
    print(data['block0583_1'])
    print(data['subkey9A1020'][:4], data['subkey9A1020'][4:6], "-----BLOCK 9A/8A")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 3
    subkeyD00100a = textwrap.wrap(data['subkeyD00100'], 132)
    H_KEY0 = data['subkeyD00100'][:6]
    L_KEY0 = data['subkeyD00100'][6:64]
    H_KEY1 = data['subkeyD00100'][64:70]
    L_KEY1 = data['subkeyD00100'][70:128]
    H_KEY2 = data['subkeyD00100'][128:134]
    L_KEY2 = data['subkeyD00100'][134:192]
    H_KEY3 = data['subkeyD00100'][192:198]
    L_KEY3 = data['subkeyD00100'][198:256]
    print(data['block0583_2'])
    print(data['subkey901020'][:4], data['subkey901020'][4:6], "-----BLOCK 90/D0")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 4
    subkey990100a = textwrap.wrap(data['subkey990100'], 132)
    H_KEY0 = data['subkey990100'][:6]
    L_KEY0 = data['subkey990100'][6:64]
    H_KEY1 = data['subkey990100'][64:70]
    L_KEY1 = data['subkey990100'][70:128]
    H_KEY2 = data['subkey990100'][128:134]
    L_KEY2 = data['subkey990100'][134:192]
    H_KEY3 = data['subkey990100'][192:198]
    L_KEY3 = data['subkey990100'][198:256]
    print(data['block0583_3'])
    print(data['subkey991020'][:4], data['subkey991020'][4:6], "-----BLOCK 99/99")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 5
    subkey880100a = textwrap.wrap(data['subkey880100'], 132)
    H_KEY0 = data['subkey880100'][:6]
    L_KEY0 = data['subkey880100'][6:64]
    H_KEY1 = data['subkey880100'][64:70]
    L_KEY1 = data['subkey880100'][70:128]
    H_KEY2 = data['subkey880100'][128:134]
    L_KEY2 = data['subkey880100'][134:192]
    H_KEY3 = data['subkey880100'][192:198]
    L_KEY3 = data['subkey880100'][198:256]
    print(data['block0583_4'])
    print(data['subkey981020'][:4], data['subkey981020'][4:6], "-----BLOCK 98/88")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 6
    subkey8A0200a = textwrap.wrap(data['subkey8A0200'], 132)
    H_KEY0 = data['subkey8A0200'][:6]
    L_KEY0 = data['subkey8A0200'][6:64]
    H_KEY1 = data['subkey8A0200'][64:70]
    L_KEY1 = data['subkey8A0200'][70:128]
    H_KEY2 = data['subkey8A0200'][128:134]
    L_KEY2 = data['subkey8A0200'][134:192]
    H_KEY3 = data['subkey8A0200'][192:198]
    L_KEY3 = data['subkey8A0200'][198:256]
    print(data['block0583_5'])
    print(data['subkeyAA2020'][:4], data['subkeyAA2020'][4:6], "-----BLOCK AA/8A")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 7
    subkeyD00200a = textwrap.wrap(data['subkeyD00200'], 132)
    H_KEY0 = data['subkeyD00200'][:6]
    L_KEY0 = data['subkeyD00200'][6:64]
    H_KEY1 = data['subkeyD00200'][64:70]
    L_KEY1 = data['subkeyD00200'][70:128]
    H_KEY2 = data['subkeyD00200'][128:134]
    L_KEY2 = data['subkeyD00200'][134:192]
    H_KEY3 = data['subkeyD00200'][192:198]
    L_KEY3 = data['subkeyD00200'][198:256]
    print(data['block0583_6'])
    print(data['subkeyA02020'][:4], data['subkeyA02020'][4:6], "----BLOCK A0/D0")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 8
    subkey990200a = textwrap.wrap(data['subkey990200'], 132)
    H_KEY0 = data['subkey990200'][:6]
    L_KEY0 = data['subkey990200'][6:64]
    H_KEY1 = data['subkey990200'][64:70]
    L_KEY1 = data['subkey990200'][70:128]
    H_KEY2 = data['subkey990200'][128:134]
    L_KEY2 = data['subkey990200'][134:192]
    H_KEY3 = data['subkey990200'][192:198]
    L_KEY3 = data['subkey990200'][198:256]
    print(data['blockBB0583_7'])
    print(data['subkeyA92020'][:4], data['subkeyA92020'][4:6], "-----BLOCK A9/99")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 9
    subkey880200a = textwrap.wrap(data['subkey880200'], 132)
    H_KEY0 = data['subkey880200'][:6]
    L_KEY0 = data['subkey880200'][6:64]
    H_KEY1 = data['subkey880200'][64:70]
    L_KEY1 = data['subkey880200'][70:128]
    H_KEY2 = data['subkey880200'][128:134]
    L_KEY2 = data['subkey880200'][134:192]
    H_KEY3 = data['subkey880200'][192:198]
    L_KEY3 = data['subkey880200'][198:256]
    print(data['blockBB0583_8'])
    print(data['subkeyA82020'][:4], data['subkeyA82020'][4:6], "-----BLOCK A8/88")
    print(H_KEY0[:6], L_KEY0)
    print(H_KEY1[:6], L_KEY1)
    print(H_KEY2[:6], L_KEY2)
    print(H_KEY3[:6], L_KEY3, separator)

    # Block 10
    H_KEY0 = data['subkey010E'][:32]
    H_KEY1 = data['subkey010E'][32:64]
    print(data['block0323'])
    print(data['subkey010E10'][:4], data['subkey010E10'][4:6], "------BLOCK 01")
    print(tab, H_KEY0)
    print(tab, H_KEY1, separator)

    # Block 11
    H_KEY0 = data['subkey8110'][:32]
    H_KEY1 = data['subkey8110'][32:64]
    print(data['block0622'])
    print(data['subkey811000'], "   -----BLOCK 81")
    print(tab, H_KEY0)
    print(tab, H_KEY1, separator)

    # Block 12
    H_KEY0 = data['subkeyXX0000'][:2]
    L_KEY0 = data['subkeyXX0000'][2:34]
    H_KEY1 = data['subkeyXX0000'][34:36]
    L_KEY1 = data['subkeyXX0000'][36:68]
    H_KEY2 = data['subkeyXX0000'][68:70]
    L_KEY2 = data['subkeyXX0000'][70:]
    print(data['block0436'])
    print(data['subkey000010'][:4], data['subkey000010'][4:6], "-----BLOCK 00")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1)
    print(H_KEY2[:2], H_KEY2[2:], L_KEY2, separator)

    # Block 13
    subkeyXX8A10a = textwrap.wrap(data['subkeyXX8A10'], 16) # This variable was defined but not used in the original script except for textwrap which was also not printed directly
    H_KEY0 = data['subkeyXX8A10'][:2]
    L_KEY0 = data['subkeyXX8A10'][2:34]
    H_KEY1 = data['subkeyXX8A10'][34:36]
    L_KEY1 = data['subkeyXX8A10'][36:68]
    H_KEY2 = data['subkeyXX8A10'][68:70]
    L_KEY2 = data['subkeyXX8A10'][70:102]
    H_KEY3 = data['subkeyXX8A10'][102:104]
    L_KEY3 = data['subkeyXX8A10'][104:]
    print(data['block0746'])
    print(data['subkey8A10'], "-----BLOCK 8A")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1)
    print(H_KEY2[:2], H_KEY2[2:], L_KEY2)
    print(H_KEY3[:2], H_KEY3[2:], L_KEY3, separator)

    # Block 14
    H_KEY0 = data['subkeyXX8010'][:2]
    L_KEY0 = data['subkeyXX8010'][2:34]
    H_KEY1 = data['subkeyXX8010'][34:36]
    L_KEY1 = data['subkeyXX8010'][36:68]
    print(data['block0724'])
    print(data['subkey8010'], "-----BLOCK 8A")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 15
    H_KEY0 = data['subkey8A0100_2'][:8]
    L_KEY0 = data['subkey8A0100_2'][8:66]
    H_KEY1 = data['subkey8A0100_2'][66:74]
    L_KEY1 = data['subkey8A0100_2'][74:132]
    print(data['block0744_0'])
    print(data['subkey9A20'][:4], "-----BLOCK 9A/8A ")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 16
    H_KEY0 = data['subkeyD00100_2'][:8]
    L_KEY0 = data['subkeyD00100_2'][8:66]
    H_KEY1 = data['subkeyD00100_2'][66:74]
    L_KEY1 = data['subkeyD00100_2'][74:132]
    print(data['block0744_1'])
    print(data['subkey9020'][:4], "-----BLOCK 90/D0")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 17
    H_KEY0 = data['subkey990100_2'][:8]
    L_KEY0 = data['subkey990100_2'][8:66]
    H_KEY1 = data['subkey990100_2'][66:74]
    L_KEY1 = data['subkey990100_2'][74:132]
    print(data['block0744_2'])
    print(data['subkey9920'][:4], "-----BLOCK 99/99")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 18
    H_KEY0 = data['subkey8801300'][:8]
    L_KEY0 = data['subkey8801300'][8:66]
    H_KEY1 = data['subkey8801300'][66:74]
    L_KEY1 = data['subkey8801300'][74:132]
    print(data['block0744_3'])
    print(data['subkey9820'][:4], "-----BLOCK 98/88")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 19
    subkey8A0300a = textwrap.wrap(data['subkey8A0300'], 132) # Defined but unused in print
    H_KEY0 = data['subkey8A0300'][:8]
    L_KEY0 = data['subkey8A0300'][8:66]
    H_KEY1 = data['subkey8A0300'][66:74]
    L_KEY1 = data['subkey8A0300'][74:132]
    print(data['block0744_4'])
    print(data['subkeyBA20'][:4], "-----BLOCK BA/8A")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 20
    subkey9903300a = textwrap.wrap(data['subkey9903300'], 132) # Defined but unused in print
    H_KEY0 = data['subkey9903300'][:8]
    L_KEY0 = data['subkey9903300'][8:66]
    H_KEY1 = data['subkey9903300'][66:74]
    L_KEY1 = data['subkey9903300'][74:132]
    print(data['block0744_5'])
    print(data['subkeyB920'][:4], "-----BLOCK B0/D0")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 21
    subkey980300a = textwrap.wrap(data['subkey980300'], 132) # Defined but unused in print
    H_KEY0 = data['subkey980300'][:8]
    L_KEY0 = data['subkey980300'][8:66]
    H_KEY1 = data['subkey980300'][66:74]
    L_KEY1 = data['subkey980300'][74:132]
    print(data['block0744_6'])
    print(data['subkeyB820'][:4], "-----BLOCK B9/99")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 22
    subkey880300a = textwrap.wrap(data['subkey880300'], 132) # Defined but unused in print
    H_KEY0 = data['subkey880300'][:8]
    L_KEY0 = data['subkey880300'][8:66]
    H_KEY1 = data['subkey880300'][66:74]
    L_KEY1 = data['subkey880300'][74:132]
    print(data['block0744_7'])
    print(data['subkeyB820_2'][:4], "-----BLOCK B8/88")
    print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

    # Block 23 (LAST BLOCK)
    subkey010400a = textwrap.wrap(data['subkey010400'], 137) # Defined but unused
    H_KEY0 = data['subkey010400'][:8]
    L_KEY0 = data['subkey010400'][8:76]
    H_KEY1 = data['subkey010400'][76:144]
    L_KEY1 = data['subkey010400'][144:]
    print(data['block0904'])
    print(data['subkey0304'][:4], "-----LAST BLOCK")
    print(H_KEY0[:4], H_KEY0[4:], L_KEY0[:6], L_KEY0[6:10], L_KEY0[10:12], L_KEY0[12:20], L_KEY0[20:], end=' ')
    print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)

def main():
    PATH = input("Input DIRECTORY here: ")

    # define how date time will be presented
    date = time.strftime("%d.%m.%Y-%H.%M")
    print(date)

    # define path to the file you want to convert and shows the content of the directory so you can choose your files to process.
    path_val = os.path.join(os.path.expanduser(PATH + "/"))  # , 'test.dat')
    mypath = path_val

    # print the dir content
    f_list = []
    for (dirpath, dirnames, filenames) in walk(mypath):
        f_list.extend(filenames)
        print("\n".join(f_list))
        break

    print("\nPath to files:\n", path_val)
    filename0 = input('\nInput binary(XXX.bin) file from the list above: ')
    filename = path_val + filename0

    try:
        with open(filename, 'rb') as f:
            f.seek(0x0, 0)  # 0E0000 if you use extracted block as .bin file change address to 0x0
            data = f.read()
    except Exception as e:
        print("Error reading file:", filename, e)
        sys.exit(2)

    extracted = extract_nagra3_data(data)
    print_nagra3_data(extracted)

if __name__ == "__main__":
    main()
