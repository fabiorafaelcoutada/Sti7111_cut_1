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
#from os import listdir
import time

# Py3 input
try:
    input = raw_input
except NameError:
    pass

def get_input(prompt):
    return input(prompt)

# PATH = binascii.hexlify(raw_input("Input DIRECTORY here: ")).decode('hex')
PATH = get_input("Input DIRECTORY here: ")

# define how date time will be presented
date = time.strftime("%d.%m.%Y-%H.%M")
print(date)

# define path to the file you want to convert and shows the content of the directory so you can choose your files to process.
path = os.path.join(os.path.expanduser(PATH + "/"))  # , 'test.dat')
mypath = path

# print the dir content
f = []
for (dirpath, dirnames, filenames) in walk(mypath):
	f.extend(filenames)
	f = "\n".join(f[:])
	print(f)
	break

print("\nPath to files:\n", path)
# filename0 = str(raw_input('\nInput binary(XXX.bin) file from the list above: ')).encode('hex').decode('hex')
filename0 = get_input('\nInput binary(XXX.bin) file from the list above: ')

filename = path + filename0
with open(filename, 'rb') as f:
	content = f.read()

######### if you want to print the input data: uncomment the line bellow  ###########
# print(binascii.hexlify(content)).decode('hex').encode('hex').upper()

try:
	with open(filename, 'rb') as f:
		f.seek(0x0, 0)  # 0E0000 if you use extracted block as .bin file change address to 0x0
		data = f.read()
except:
	print("Error reading file:", filename)
	sys.exit(2)

def to_hex(data_slice):
    return binascii.hexlify(data_slice).upper().decode('ascii')

DESCRIPTOR = str(to_hex(data[0:4]))
NUID = str(to_hex(data[4:8]))
NPROVIDER = str(to_hex(data[8:10]))
PROVIDERID = str(to_hex(data[10:12]))
ARCH = str(to_hex(data[12:14]))
CWKEYDESC = str(to_hex(data[14:15]))
Hextable = str(to_hex(data[18:19]))
TLENGHT = str(to_hex(data[17:18]))

BLOCK = str(to_hex(data[19:153]))

eCK0 = str(to_hex(data[19:35]))
eCK1 = str(to_hex(data[35:51]))
eCK2 = str(to_hex(data[51:67]))
eCK3 = str(to_hex(data[67:83]))
eCK4 = str(to_hex(data[83:99]))
eCK5 = str(to_hex(data[99:115]))
eCK6 = str(to_hex(data[115:131]))
eCK7 = str(to_hex(data[131:147]))
print()
print('CSCKeyDescriptor: ', DESCRIPTOR, "(LEN of CWPK block)")
print('NUID: ', NUID)
print('Max Number of Provider IDs: ',NPROVIDER)
print('Provider ID: ', PROVIDERID, "; SysID ", format(int(PROVIDERID, 16)))
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

############################
separator = "\n"
tab = "    "
block0583_1 = 140
block0583 = str(to_hex(data[147:149]))
subkey8A0010 = str(to_hex(data[149:153]))
subkey8A_256 = (to_hex(data[152:280]))
subkey8A_256a = textwrap.wrap(subkey8A_256, 32)
print(block0583)
print(subkey8A0010[:4], subkey8A0010[4:6], "-----BLOCK 8A -1024-???? ")
print(separator.join(subkey8A_256a), separator)
#print "NEXT counter = ", (block0583_1 + 5) + 135

def process_nagra_block(data, offset, description, separator):
    block = to_hex(data[offset : offset + 2])
    subkey_header = to_hex(data[offset + 2 : offset + 5])
    subkey_body = to_hex(data[offset + 5 : offset + 5 + 132])

    h_key0 = subkey_body[:6]
    l_key0 = subkey_body[6:64]
    h_key1 = subkey_body[64:70]
    l_key1 = subkey_body[70:128]
    h_key2 = subkey_body[128:134]
    l_key2 = subkey_body[134:192]
    h_key3 = subkey_body[192:198]
    l_key3 = subkey_body[198:256]

    print(block)
    print(subkey_header[:4], subkey_header[4:6], description)
    print(h_key0[:6], l_key0)
    print(h_key1[:6], l_key1)
    print(h_key2[:6], l_key2)
    print(h_key3[:6], l_key3, separator)

process_nagra_block(data, 280, "-----BLOCK 9A/8A", separator)
process_nagra_block(data, 413, "-----BLOCK 90/D0", separator)
process_nagra_block(data, 546, "-----BLOCK 99/99", separator)
process_nagra_block(data, 679, "-----BLOCK 98/88", separator)
process_nagra_block(data, 812, "-----BLOCK AA/8A", separator)
process_nagra_block(data, 945, "----BLOCK A0/D0", separator)
process_nagra_block(data, 1078, "-----BLOCK A9/99", separator)
process_nagra_block(data, 1211, "-----BLOCK A8/88", separator)

BB0323 = 1344
block0323 = (to_hex(data[BB0323:(BB0323 + 2)]))
subkey010E10 = (to_hex(data[(BB0323 + 2):(BB0323 + 5)]))
subkey010E = (to_hex(data[(BB0323 + 5):((BB0323 + 5) + 32)]))
H_KEY0 = subkey010E[:32]
H_KEY1 = subkey010E[32:64]
print(block0323)
print(subkey010E10[:4], subkey010E10[4:6], "------BLOCK 01")
print(tab, H_KEY0)
print(tab, H_KEY1, separator)
#print "NEXT counter = ", (BB0323 + 5) + 32

BB0622 = 1381
block0622 = (to_hex(data[BB0622:(BB0622 + 2)]))
subkey811000 = (to_hex(data[(BB0622 + 2):(BB0622 + 4)]))
subkey8110 = (to_hex(data[(BB0622 + 4):((BB0622 + 4) + 32)]))
H_KEY0 = subkey8110[:32]
H_KEY1 = subkey8110[32:64]
print(block0622)
print(subkey811000, "   -----BLOCK 81")
print(tab, H_KEY0)
print(tab, H_KEY1, separator)
#print "NEXT counter = ", (BB0622 + 5) + 31

BB0436 = 1417
block0436 = (to_hex(data[BB0436:(BB0436 + 2)]))
subkey000010 = (to_hex(data[(BB0436 + 2):(BB0436 + 5)]))
subkeyXX0000 = (to_hex(data[(BB0436 + 5):((BB0436 + 5) + 51)]))
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
#print "NEXT counter = ", (BB0436 + 6) + 50

BB0746 = 1473
block0746 = (to_hex(data[BB0746:(BB0746 + 2)]))
subkey8A10 = (to_hex(data[(BB0746 + 2):(BB0746 + 4)]))
subkeyXX8A10 = (to_hex(data[(BB0746 + 4):((BB0746 + 4) + 68)]))
subkeyXX8A10a = textwrap.wrap(subkeyXX8A10, 16)
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
#print "NEXT counter = ", (BB0746 + 6) + 66

BB0724 = 1545
block0724 = (to_hex(data[BB0724:(BB0724 + 2)]))
subkey8010 = (to_hex(data[(BB0724 + 2):(BB0724 + 4)]))
subkeyXX8010 = (to_hex(data[(BB0724 + 4):((BB0724 + 4) + 68)]))
H_KEY0 = subkeyXX8010[:2]
L_KEY0 = subkeyXX8010[2:34]
H_KEY1 = subkeyXX8010[34:36]
L_KEY1 = subkeyXX8010[36:68]
print(block0724)
print(subkey8010, "-----BLOCK 8A")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
#print "NEXT counter = ", (BB0724 + 6) + 32

BB0744_0 = 1583
block0744_0 = (to_hex(data[BB0744_0:(BB0744_0 + 2)]))
subkey9A20 = (to_hex(data[(BB0744_0 + 2):(BB0744_0 + 4)]))
subkey8A0100 = (to_hex(data[(BB0744_0 + 4):((BB0744_0 + 4) + 132)]))
H_KEY0 = subkey8A0100[:8]
L_KEY0 = subkey8A0100[8:66]
H_KEY1 = subkey8A0100[66:74]
L_KEY1 = subkey8A0100[74:132]
print(block0744_0)
print(subkey9A20[:4], "-----BLOCK 9A/8A ")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
#print "NEXT counter = ", (BB0744_0 + 6) + 64

BB0744_1 = 1653
block0744_1 = (to_hex(data[BB0744_1:(BB0744_1 + 2)]))
subkey9020 = (to_hex(data[(BB0744_1 + 2):(BB0744_1 + 4)]))
subkeyD00100 = (to_hex(data[(BB0744_1 + 4):((BB0744_1 + 4) + 68)]))
H_KEY0 = subkeyD00100[:8]
L_KEY0 = subkeyD00100[8:66]
H_KEY1 = subkeyD00100[66:74]
L_KEY1 = subkeyD00100[74:132]
print(block0744_1)
print(subkey9020[:4], "-----BLOCK 90/D0")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
#print "NEXT counter = ", (BB0744_1 + 6) + 64

BB0744_2 = 1723
block0744_2 = (to_hex(data[BB0744_2:(BB0744_2 + 2)]))
subkey9920 = (to_hex(data[(BB0744_2 + 2):(BB0744_2 + 4)]))
subkey990100 = (to_hex(data[(BB0744_2 + 4):((BB0744_2 + 4) + 68)]))
H_KEY0 = subkey990100[:8]
L_KEY0 = subkey990100[8:66]
H_KEY1 = subkey990100[66:74]
L_KEY1 = subkey990100[74:132]
print(block0744_2)
print(subkey9920[:4], "-----BLOCK 99/99")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
#print "NEXT counter = ", (BB0744_2 + 6) + 64

BB0744_3 = 1793
block0744_3 = (to_hex(data[BB0744_3:(BB0744_3 + 2)]))
subkey9820 = (to_hex(data[(BB0744_3 + 2):(BB0744_3 + 4)]))
subkey8801300 = (to_hex(data[(BB0744_3 + 4):((BB0744_3 + 4) + 68)]))
H_KEY0 = subkey8801300[:8]
L_KEY0 = subkey8801300[8:66]
H_KEY1 = subkey8801300[66:74]
L_KEY1 = subkey8801300[74:132]
print(block0744_3)
print(subkey9820[:4], "-----BLOCK 98/88")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
#print "NEXT counter = ", (BB0744_3 + 6) + 64

BB0744_4 = 1863
block0744_4 = (to_hex(data[BB0744_4:(BB0744_4 + 2)]))
subkeyBA20 = (to_hex(data[(BB0744_4 + 2):(BB0744_4 + 4)]))
subkey8A0300 = (to_hex(data[(BB0744_4 + 4):((BB0744_4 + 4) + 132)]))
subkey8A0300a = textwrap.wrap(subkey8A0300, 132)
H_KEY0 = subkey8A0300[:8]
L_KEY0 = subkey8A0300[8:66]
H_KEY1 = subkey8A0300[66:74]
L_KEY1 = subkey8A0300[74:132]
# H_KEY2 = subkey8A0300[132:140]
# L_KEY2 = subkey8A0300[140:198]
# H_KEY3 = subkey8A0300[198:206]
# L_KEY3 = subkey8A0300[206:]
print(block0744_4)
print(subkeyBA20[:4], "-----BLOCK BA/8A")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_4 + 6) + 64

BB0744_5 = 1933
block0744_5 = (to_hex(data[BB0744_5:(BB0744_5 + 2)]))
subkeyB920 = (to_hex(data[(BB0744_5 + 2):(BB0744_5 + 4)]))
subkey9903300 = (to_hex(data[(BB0744_5 + 4):((BB0744_5 + 4) + 132)]))
subkey9903300a = textwrap.wrap(subkey9903300, 132)
H_KEY0 = subkey9903300[:8]
L_KEY0 = subkey9903300[8:66]
H_KEY1 = subkey9903300[66:74]
L_KEY1 = subkey9903300[74:132]
# H_KEY2 = subkey9903300[132:140]
# L_KEY2 = subkey9903300[140:198]
# H_KEY3 = subkey9903300[198:206]
# L_KEY3 = subkey9903300[206:]
print(block0744_5)
print(subkeyB920[:4], "-----BLOCK B0/D0")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_5 + 6) + 64

BB0744_6 = 2003
block0744_6 = (to_hex(data[BB0744_6:(BB0744_6 + 2)]))
subkeyB820 = (to_hex(data[(BB0744_6 + 2):(BB0744_6 + 4)]))
subkey980300 = (to_hex(data[(BB0744_6 + 4):((BB0744_6 + 4) + 132)]))
subkey980300a = textwrap.wrap(subkey980300, 132)
H_KEY0 = subkey980300[:8]
L_KEY0 = subkey980300[8:66]
H_KEY1 = subkey980300[66:74]
L_KEY1 = subkey980300[74:132]
# H_KEY2 = subkey980300[132:140]
# L_KEY2 = subkey980300[140:198]
# H_KEY3 = subkey980300[198:206]
# L_KEY3 = subkey980300[206:]
print(block0744_6)
print(subkeyB820[:4], "-----BLOCK B9/99")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_6 + 6) + 64

BB0744_7 = 2073
block0744_7 = (to_hex(data[BB0744_7:(BB0744_7 + 2)]))
subkeyB820 = (to_hex(data[(BB0744_7 + 2):(BB0744_7 + 4)]))
subkey880300 = (to_hex(data[(BB0744_7 + 4):((BB0744_7 + 4) + 132)]))
subkey880300a = textwrap.wrap(subkey880300, 132)
H_KEY0 = subkey880300[:8]
L_KEY0 = subkey880300[8:66]
H_KEY1 = subkey880300[66:74]
L_KEY1 = subkey880300[74:132]
# H_KEY2 = subkey880300[132:140]
# L_KEY2 = subkey880300[140:198]
# H_KEY3 = subkey880300[198:206]
# L_KEY3 = subkey880300[206:]
print(block0744_7)
print(subkeyB820[:4], "-----BLOCK B8/88")
print(H_KEY0[:2], H_KEY0[2:], L_KEY0)
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0744_7 + 6) + 64

BB0904 = 2143
block0904 = (to_hex(data[BB0904:(BB0904 + 2)]))
subkey0304 = (to_hex(data[(BB0904 + 2):(BB0904 + 4)]))
subkey010400 = (to_hex(data[(BB0904 + 4):((BB0904 + 4) + 137)]))
subkey010400a = textwrap.wrap(subkey010400, 137)
H_KEY0 = subkey010400[:8]
L_KEY0 = subkey010400[8:76]
H_KEY1 = subkey010400[76:144]
L_KEY1 = subkey010400[144:]
# H_KEY2 = subkey010400[132:140]
# L_KEY2 = subkey010400[140:198]
# H_KEY3 = subkey010400[198:206]
# L_KEY3 = subkey010400[206:]
print(block0904)
print(subkey0304[:4], "-----LAST BLOCK")
print(H_KEY0[:4], H_KEY0[4:], L_KEY0[:6], L_KEY0[6:10], L_KEY0[10:12], L_KEY0[12:20], L_KEY0[20:], end=' ')
print(H_KEY1[:2], H_KEY1[2:], L_KEY1, separator)
# print H_KEY2[:2], H_KEY2[2:], L_KEY2
# print H_KEY3[:2], H_KEY3[2:], L_KEY3
#print "NEXT counter = ", (BB0904 + 6) + 64

# print file to output.txt file
# f = f.open('BLOCK_0AE3.txt', 'a')
# print >> f.write('...\n')
