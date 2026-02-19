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

# Helper function for hex conversion in Py3
def to_hex(data):
    return binascii.hexlify(data).decode('ascii').upper()

try:
    input_dir = input("Input DIRECTORY here: ").strip()
except EOFError:
    sys.exit(0)

PATH = input_dir

# define how date time will be presented
date = time.strftime("%d.%m.%Y-%H.%M")
print(date)

# define path to the file you want to convert and shows the content of the directory so you can choose your files to process.
path = os.path.join(os.path.expanduser(PATH + "/"))
mypath = path

# print the dir content
f = []
for (dirpath, dirnames, filenames) in os.walk(mypath):
    f.extend(filenames)
    f_str = "\n".join(f[:])
    print(f_str)
    break

print("\nPath to files:\n", path)
try:
    filename0 = input('\nInput binary(XXX.bin) file from the list above: ').strip()
except EOFError:
    sys.exit(0)

filename = os.path.join(path, filename0)

try:
    with open(filename, 'rb') as f:
        content = f.read()
except IOError:
    print("Error reading file:", filename)
    sys.exit(2)

# Open secure output file
output_filename = f"extracted_keys_{int(time.time())}.txt"
# restrict permissions to owner only (read/write)
fd = os.open(output_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
out_f = os.fdopen(fd, 'w')

print(f"\n[INFO] Sensitive data will be written to {output_filename}")
print(f"[INFO] File permissions set to 0600 (owner read/write only)")

def log(msg, sensitive=False):
    if sensitive:
        out_f.write(msg + "\n")
        # Masked output to console or just placeholder
        # print("[SENSITIVE DATA SAVED TO FILE]")
    else:
        out_f.write(msg + "\n")
        print(msg)

try:
    # Use content read above directly
    data = content
    # If explicit seek was needed, slicing handles it naturally if offset is relative to start
    # Original code: f.seek(0x0, 0) -> data = f.read()
    # So data is full content.
except Exception as e:
    print("Error processing file:", e)
    sys.exit(2)

DESCRIPTOR = to_hex(data[0:4])
NUID = to_hex(data[4:8])
NPROVIDER = to_hex(data[8:10])
PROVIDERID = to_hex(data[10:12])
ARCH = to_hex(data[12:14])
CWKEYDESC = to_hex(data[14:15])
Hextable = to_hex(data[18:19])
TLENGHT = to_hex(data[17:18])

BLOCK = to_hex(data[19:153])

eCK0 = to_hex(data[19:35])
eCK1 = to_hex(data[35:51])
eCK2 = to_hex(data[51:67])
eCK3 = to_hex(data[67:83])
eCK4 = to_hex(data[83:99])
eCK5 = to_hex(data[99:115])
eCK6 = to_hex(data[115:131])
eCK7 = to_hex(data[131:147])

log('')
log(f'CSCKeyDescriptor:  {DESCRIPTOR} (LEN of CWPK block)')
log(f'NUID:  {NUID}')
log(f'Max Number of Provider IDs: {NPROVIDER}')
log(f'Provider ID:  {PROVIDERID} ; SysID  {int(PROVIDERID, 16)}')
log(f'Security Architecture:  {ARCH}')
log(f'CW Key descriptor:  {CWKEYDESC}')
log(f'Hex bytes:  {Hextable}')
log(f'Storage table length: 0x{TLENGHT}')

log(f'eCK0: {eCK0}', sensitive=True)
print('eCK0: [SAVED TO FILE]')
log(f'eCK1: {eCK1}', sensitive=True)
print('eCK1: [SAVED TO FILE]')
log(f'eCK2: {eCK2}', sensitive=True)
print('eCK2: [SAVED TO FILE]')
log(f'eCK3: {eCK3}', sensitive=True)
print('eCK3: [SAVED TO FILE]')
log(f'eCK4: {eCK4}', sensitive=True)
print('eCK4: [SAVED TO FILE]')
log(f'eCK5: {eCK5}', sensitive=True)
print('eCK5: [SAVED TO FILE]')
log(f'eCK6: {eCK6}', sensitive=True)
print('eCK6: [SAVED TO FILE]')
log(f'eCK7: {eCK7}', sensitive=True)
print('eCK7: [SAVED TO FILE]')


log('')
log("|||||||||||||||||||||||||||||||||||||")
log("|| New datakeys protection level  || ")
log("|||||||||||||||||||||||||||||||||||||")
log('')

############################
separator = "\n"
tab = "    "
block0583_1 = 140
block0583 = to_hex(data[147:149])
subkey8A0010 = to_hex(data[149:153])
subkey8A_256 = to_hex(data[152:280])
subkey8A_256a = textwrap.wrap(subkey8A_256, 32)
log(block0583)
log(f"{subkey8A0010[:4]} {subkey8A0010[4:6]} -----BLOCK 8A -1024-???? ")
log(separator.join(subkey8A_256a) + separator, sensitive=True)
print("[Block 8A Data Saved to File]")


BB0583_1 = 280
block0583_1 = to_hex(data[BB0583_1:(BB0583_1 + 2)])
subkey9A1020 = to_hex(data[(BB0583_1 + 2):(BB0583_1 + 5)])
subkey8A0100 = to_hex(data[(BB0583_1 + 5):((BB0583_1 + 5) + 132)])
subkey8A0100a = textwrap.wrap(subkey8A0100, 132)
H_KEY0 = subkey8A0100[:6]
L_KEY0 = subkey8A0100[6:64]
H_KEY1 = subkey8A0100[64:70]
L_KEY1 = subkey8A0100[70:128]
H_KEY2 = subkey8A0100[128:134]
L_KEY2 = subkey8A0100[134:192]
H_KEY3 = subkey8A0100[192:198]
L_KEY3 = subkey8A0100[198:256]
log(block0583_1)
log(f"{subkey9A1020[:4]} {subkey9A1020[4:6]} -----BLOCK 9A/8A")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block 9A/8A Keys Saved to File]")

BB0583_2 = 413
block0583_2 = to_hex(data[BB0583_2:(BB0583_2 + 2)])
subkey901020 = to_hex(data[(BB0583_2 + 2):(BB0583_2 + 5)])
subkeyD00100 = to_hex(data[(BB0583_2 + 5):((BB0583_2 + 5) + 132)])
subkeyD00100a = textwrap.wrap(subkeyD00100, 132)
H_KEY0 = subkeyD00100[:6]
L_KEY0 = subkeyD00100[6:64]
H_KEY1 = subkeyD00100[64:70]
L_KEY1 = subkeyD00100[70:128]
H_KEY2 = subkeyD00100[128:134]
L_KEY2 = subkeyD00100[134:192]
H_KEY3 = subkeyD00100[192:198]
L_KEY3 = subkeyD00100[198:256]
log(block0583_2)
log(f"{subkey901020[:4]} {subkey901020[4:6]} -----BLOCK 90/D0")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block 90/D0 Keys Saved to File]")

BB0583_3 = 546
block0583_3 = to_hex(data[BB0583_3:(BB0583_3 + 2)])
subkey991020 = to_hex(data[(BB0583_3 + 2):(BB0583_3 + 5)])
subkey990100 = to_hex(data[(BB0583_3 + 5):((BB0583_3 + 5) + 132)])
subkey990100a = textwrap.wrap(subkey990100, 132)
H_KEY0 = subkey990100[:6]
L_KEY0 = subkey990100[6:64]
H_KEY1 = subkey990100[64:70]
L_KEY1 = subkey990100[70:128]
H_KEY2 = subkey990100[128:134]
L_KEY2 = subkey990100[134:192]
H_KEY3 = subkey990100[192:198]
L_KEY3 = subkey990100[198:256]
log(block0583_3)
log(f"{subkey991020[:4]} {subkey991020[4:6]} -----BLOCK 99/99")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block 99/99 Keys Saved to File]")

BB0583_4 = 679
block0583_4 = to_hex(data[BB0583_4:(BB0583_4 + 2)])
subkey981020 = to_hex(data[(BB0583_4 + 2):(BB0583_4 + 5)])
subkey880100 = to_hex(data[(BB0583_4 + 5):((BB0583_4 + 5) + 132)])
subkey880100a = textwrap.wrap(subkey880100, 132)
H_KEY0 = subkey880100[:6]
L_KEY0 = subkey880100[6:64]
H_KEY1 = subkey880100[64:70]
L_KEY1 = subkey880100[70:128]
H_KEY2 = subkey880100[128:134]
L_KEY2 = subkey880100[134:192]
H_KEY3 = subkey880100[192:198]
L_KEY3 = subkey880100[198:256]
log(block0583_4)
log(f"{subkey981020[:4]} {subkey981020[4:6]} -----BLOCK 98/88")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block 98/88 Keys Saved to File]")

BB0583_5 = 812
block0583_5 = to_hex(data[BB0583_5:(BB0583_5 + 2)])
subkeyAA2020 = to_hex(data[(BB0583_5 + 2):(BB0583_5 + 5)])
subkey8A0200 = to_hex(data[(BB0583_5 + 5):((BB0583_5 + 5) + 132)])
subkey8A0200a = textwrap.wrap(subkey8A0200, 132)
H_KEY0 = subkey8A0200[:6]
L_KEY0 = subkey8A0200[6:64]
H_KEY1 = subkey8A0200[64:70]
L_KEY1 = subkey8A0200[70:128]
H_KEY2 = subkey8A0200[128:134]
L_KEY2 = subkey8A0200[134:192]
H_KEY3 = subkey8A0200[192:198]
L_KEY3 = subkey8A0200[198:256]
log(block0583_5)
log(f"{subkeyAA2020[:4]} {subkeyAA2020[4:6]} -----BLOCK AA/8A")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block AA/8A Keys Saved to File]")

BB0583_6 = 945
block0583_6 = to_hex(data[BB0583_6:(BB0583_6 + 2)])
subkeyA02020 = to_hex(data[(BB0583_6 + 2):(BB0583_6 + 5)])
subkeyD00200 = to_hex(data[(BB0583_6 + 5):((BB0583_6 + 5) + 132)])
subkeyD00200a = textwrap.wrap(subkeyD00200, 132)
H_KEY0 = subkeyD00200[:6]
L_KEY0 = subkeyD00200[6:64]
H_KEY1 = subkeyD00200[64:70]
L_KEY1 = subkeyD00200[70:128]
H_KEY2 = subkeyD00200[128:134]
L_KEY2 = subkeyD00200[134:192]
H_KEY3 = subkeyD00200[192:198]
L_KEY3 = subkeyD00200[198:256]
log(block0583_6)
log(f"{subkeyA02020[:4]} {subkeyA02020[4:6]} ----BLOCK A0/D0")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block A0/D0 Keys Saved to File]")

BBBB0583_7 = 1078
blockBB0583_7 = to_hex(data[BBBB0583_7:(BBBB0583_7 + 2)])
subkeyA92020 = to_hex(data[(BBBB0583_7 + 2):(BBBB0583_7 + 5)])
subkey990200 = to_hex(data[(BBBB0583_7 + 5):((BBBB0583_7 + 5) + 132)])
subkey990200a = textwrap.wrap(subkey990200, 132)
H_KEY0 = subkey990200[:6]
L_KEY0 = subkey990200[6:64]
H_KEY1 = subkey990200[64:70]
L_KEY1 = subkey990200[70:128]
H_KEY2 = subkey990200[128:134]
L_KEY2 = subkey990200[134:192]
H_KEY3 = subkey990200[192:198]
L_KEY3 = subkey990200[198:256]
log(blockBB0583_7)
log(f"{subkeyA92020[:4]} {subkeyA92020[4:6]} -----BLOCK A9/99")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block A9/99 Keys Saved to File]")

BBBB0583_8 = 1211
blockBB0583_8 = to_hex(data[BBBB0583_8:(BBBB0583_8 + 2)])
subkeyA82020 = to_hex(data[(BBBB0583_8 + 2):(BBBB0583_8 + 5)])
subkey880200 = to_hex(data[(BBBB0583_8 + 5):((BBBB0583_8 + 5) + 132)])
subkey880200a = textwrap.wrap(subkey880200, 132)
H_KEY0 = subkey880200[:6]
L_KEY0 = subkey880200[6:64]
H_KEY1 = subkey880200[64:70]
L_KEY1 = subkey880200[70:128]
H_KEY2 = subkey880200[128:134]
L_KEY2 = subkey880200[134:192]
H_KEY3 = subkey880200[192:198]
L_KEY3 = subkey880200[198:256]
log(blockBB0583_8)
log(f"{subkeyA82020[:4]} {subkeyA82020[4:6]} -----BLOCK A8/88")
log(f"{H_KEY0[:6]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:6]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:6]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:6]} {L_KEY3} {separator}", sensitive=True)
print("[Block A8/88 Keys Saved to File]")

BB0323 = 1344
block0323 = to_hex(data[BB0323:(BB0323 + 2)])
subkey010E10 = to_hex(data[(BB0323 + 2):(BB0323 + 5)])
subkey010E = to_hex(data[(BB0323 + 5):((BB0323 + 5) + 32)])
H_KEY0 = subkey010E[:32]
H_KEY1 = subkey010E[32:64]
log(block0323)
log(f"{subkey010E10[:4]} {subkey010E10[4:6]} ------BLOCK 01")
log(f"{tab} {H_KEY0}", sensitive=True)
log(f"{tab} {H_KEY1} {separator}", sensitive=True)
print("[Block 01 Keys Saved to File]")

BB0622 = 1381
block0622 = to_hex(data[BB0622:(BB0622 + 2)])
subkey811000 = to_hex(data[(BB0622 + 2):(BB0622 + 4)])
subkey8110 = to_hex(data[(BB0622 + 4):((BB0622 + 4) + 32)])
H_KEY0 = subkey8110[:32]
H_KEY1 = subkey8110[32:64]
log(block0622)
log(f"{subkey811000}    -----BLOCK 81")
log(f"{tab} {H_KEY0}", sensitive=True)
log(f"{tab} {H_KEY1} {separator}", sensitive=True)
print("[Block 81 Keys Saved to File]")

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
log(block0436)
log(f"{subkey000010[:4]} {subkey000010[4:6]} -----BLOCK 00")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:2]} {H_KEY2[2:]} {L_KEY2} {separator}", sensitive=True)
print("[Block 00 Keys Saved to File]")

BB0746 = 1473
block0746 = to_hex(data[BB0746:(BB0746 + 2)])
subkey8A10 = to_hex(data[(BB0746 + 2):(BB0746 + 4)])
subkeyXX8A10 = to_hex(data[(BB0746 + 4):((BB0746 + 4) + 68)])
subkeyXX8A10a = textwrap.wrap(subkeyXX8A10, 16)
H_KEY0 = subkeyXX8A10[:2]
L_KEY0 = subkeyXX8A10[2:34]
H_KEY1 = subkeyXX8A10[34:36]
L_KEY1 = subkeyXX8A10[36:68]
H_KEY2 = subkeyXX8A10[68:70]
L_KEY2 = subkeyXX8A10[70:102]
H_KEY3 = subkeyXX8A10[102:104]
L_KEY3 = subkeyXX8A10[104:]
log(block0746)
log(f"{subkey8A10} -----BLOCK 8A")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1}", sensitive=True)
log(f"{H_KEY2[:2]} {H_KEY2[2:]} {L_KEY2}", sensitive=True)
log(f"{H_KEY3[:2]} {H_KEY3[2:]} {L_KEY3} {separator}", sensitive=True)
print("[Block 8A Keys Saved to File]")

BB0724 = 1545
block0724 = to_hex(data[BB0724:(BB0724 + 2)])
subkey8010 = to_hex(data[(BB0724 + 2):(BB0724 + 4)])
subkeyXX8010 = to_hex(data[(BB0724 + 4):((BB0724 + 4) + 68)])
H_KEY0 = subkeyXX8010[:2]
L_KEY0 = subkeyXX8010[2:34]
H_KEY1 = subkeyXX8010[34:36]
L_KEY1 = subkeyXX8010[36:68]
log(block0724)
log(f"{subkey8010} -----BLOCK 8A")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block 8A Keys Saved to File]")

BB0744_0 = 1583
block0744_0 = to_hex(data[BB0744_0:(BB0744_0 + 2)])
subkey9A20 = to_hex(data[(BB0744_0 + 2):(BB0744_0 + 4)])
subkey8A0100 = to_hex(data[(BB0744_0 + 4):((BB0744_0 + 4) + 132)])
H_KEY0 = subkey8A0100[:8]
L_KEY0 = subkey8A0100[8:66]
H_KEY1 = subkey8A0100[66:74]
L_KEY1 = subkey8A0100[74:132]
log(block0744_0)
log(f"{subkey9A20[:4]} -----BLOCK 9A/8A ")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block 9A/8A Keys Saved to File]")

BB0744_1 = 1653
block0744_1 = to_hex(data[BB0744_1:(BB0744_1 + 2)])
subkey9020 = to_hex(data[(BB0744_1 + 2):(BB0744_1 + 4)])
subkeyD00100 = to_hex(data[(BB0744_1 + 4):((BB0744_1 + 4) + 68)])
H_KEY0 = subkeyD00100[:8]
L_KEY0 = subkeyD00100[8:66]
H_KEY1 = subkeyD00100[66:74]
L_KEY1 = subkeyD00100[74:132]
log(block0744_1)
log(f"{subkey9020[:4]} -----BLOCK 90/D0")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block 90/D0 Keys Saved to File]")

BB0744_2 = 1723
block0744_2 = to_hex(data[BB0744_2:(BB0744_2 + 2)])
subkey9920 = to_hex(data[(BB0744_2 + 2):(BB0744_2 + 4)])
subkey990100 = to_hex(data[(BB0744_2 + 4):((BB0744_2 + 4) + 68)])
H_KEY0 = subkey990100[:8]
L_KEY0 = subkey990100[8:66]
H_KEY1 = subkey990100[66:74]
L_KEY1 = subkey990100[74:132]
log(block0744_2)
log(f"{subkey9920[:4]} -----BLOCK 99/99")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block 99/99 Keys Saved to File]")

BB0744_3 = 1793
block0744_3 = to_hex(data[BB0744_3:(BB0744_3 + 2)])
subkey9820 = to_hex(data[(BB0744_3 + 2):(BB0744_3 + 4)])
subkey8801300 = to_hex(data[(BB0744_3 + 4):((BB0744_3 + 4) + 68)])
H_KEY0 = subkey8801300[:8]
L_KEY0 = subkey8801300[8:66]
H_KEY1 = subkey8801300[66:74]
L_KEY1 = subkey8801300[74:132]
log(block0744_3)
log(f"{subkey9820[:4]} -----BLOCK 98/88")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block 98/88 Keys Saved to File]")

BB0744_4 = 1863
block0744_4 = to_hex(data[BB0744_4:(BB0744_4 + 2)])
subkeyBA20 = to_hex(data[(BB0744_4 + 2):(BB0744_4 + 4)])
subkey8A0300 = to_hex(data[(BB0744_4 + 4):((BB0744_4 + 4) + 132)])
subkey8A0300a = textwrap.wrap(subkey8A0300, 132)
H_KEY0 = subkey8A0300[:8]
L_KEY0 = subkey8A0300[8:66]
H_KEY1 = subkey8A0300[66:74]
L_KEY1 = subkey8A0300[74:132]
log(block0744_4)
log(f"{subkeyBA20[:4]} -----BLOCK BA/8A")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block BA/8A Keys Saved to File]")

BB0744_5 = 1933
block0744_5 = to_hex(data[BB0744_5:(BB0744_5 + 2)])
subkeyB920 = to_hex(data[(BB0744_5 + 2):(BB0744_5 + 4)])
subkey9903300 = to_hex(data[(BB0744_5 + 4):((BB0744_5 + 4) + 132)])
subkey9903300a = textwrap.wrap(subkey9903300, 132)
H_KEY0 = subkey9903300[:8]
L_KEY0 = subkey9903300[8:66]
H_KEY1 = subkey9903300[66:74]
L_KEY1 = subkey9903300[74:132]
log(block0744_5)
log(f"{subkeyB920[:4]} -----BLOCK B0/D0")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block B0/D0 Keys Saved to File]")

BB0744_6 = 2003
block0744_6 = to_hex(data[BB0744_6:(BB0744_6 + 2)])
subkeyB820 = to_hex(data[(BB0744_6 + 2):(BB0744_6 + 4)])
subkey980300 = to_hex(data[(BB0744_6 + 4):((BB0744_6 + 4) + 132)])
subkey980300a = textwrap.wrap(subkey980300, 132)
H_KEY0 = subkey980300[:8]
L_KEY0 = subkey980300[8:66]
H_KEY1 = subkey980300[66:74]
L_KEY1 = subkey980300[74:132]
log(block0744_6)
log(f"{subkeyB820[:4]} -----BLOCK B9/99")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block B9/99 Keys Saved to File]")

BB0744_7 = 2073
block0744_7 = to_hex(data[BB0744_7:(BB0744_7 + 2)])
subkeyB820 = to_hex(data[(BB0744_7 + 2):(BB0744_7 + 4)])
subkey880300 = to_hex(data[(BB0744_7 + 4):((BB0744_7 + 4) + 132)])
subkey880300a = textwrap.wrap(subkey880300, 132)
H_KEY0 = subkey880300[:8]
L_KEY0 = subkey880300[8:66]
H_KEY1 = subkey880300[66:74]
L_KEY1 = subkey880300[74:132]
log(block0744_7)
log(f"{subkeyB820[:4]} -----BLOCK B8/88")
log(f"{H_KEY0[:2]} {H_KEY0[2:]} {L_KEY0}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Block B8/88 Keys Saved to File]")

BB0904 = 2143
block0904 = to_hex(data[BB0904:(BB0904 + 2)])
subkey0304 = to_hex(data[(BB0904 + 2):(BB0904 + 4)])
subkey010400 = to_hex(data[(BB0904 + 4):((BB0904 + 4) + 137)])
subkey010400a = textwrap.wrap(subkey010400, 137)
H_KEY0 = subkey010400[:8]
L_KEY0 = subkey010400[8:76]
H_KEY1 = subkey010400[76:144]
L_KEY1 = subkey010400[144:]
log(block0904)
log(f"{subkey0304[:4]} -----LAST BLOCK")
log(f"{H_KEY0[:4]} {H_KEY0[4:]} {L_KEY0[:6]} {L_KEY0[6:10]} {L_KEY0[10:12]} {L_KEY0[12:20]} {L_KEY0[20:]}", sensitive=True)
log(f"{H_KEY1[:2]} {H_KEY1[2:]} {L_KEY1} {separator}", sensitive=True)
print("[Last Block Keys Saved to File]")

out_f.close()
