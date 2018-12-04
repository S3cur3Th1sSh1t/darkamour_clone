#!/usr/bin/env python3

import sys

try:
    if sys.argv[1] == "--count":
        data = sys.stdin.read()
        count = 0
        for byte in data.split():
            count += 1
        print("#define array_len {}\n".format(count))
        exit()
except IndexError:
    pass

bytes = ""
key = 0x8274058120583047
data = sys.stdin.read()
count = 0
for byte in data.split():
    byte = byte.replace(',', "")
    if int(byte, 16) != 0x00:
        crypt_byte = int(byte, 16) ^ key
    else:
        crypt_byte = 0x3a11739dafdda332
    if count == 16:
        bytes += "{},\n".format(hex(crypt_byte))
        count = 0
    else:
        bytes += "{}, ".format(hex(crypt_byte))
        count += 1

bytes = bytes.strip()
if bytes[len(bytes)-1] == ',':
    bytes = bytes[:len(bytes)-1]

print(bytes)
