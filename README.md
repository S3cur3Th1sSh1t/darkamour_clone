# Windows AV Evasion Tool

Store and execute an encrypted windows binary from inside memory, without a single bit touching disk.

## Usage

```
DarkArmour by Dylan Halls (v0.2)

usage: darkarmour.py [-h] [-f FILE] [-S SHELLCODE] [-b] [-d] [-s] [-r]
                     [-k KEY] [-o OUTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  file to crypt, assumed as binary if not told otherwise
  -S SHELLCODE, --shellcode SHELLCODE
                        file contating the shellcode, needs to be in the
                        'msfvenom -f raw' style format
  -b, --binary          provide if file is a binary exe
  -d, --dll             use reflective dll injection to execute the binary
                        inside another process
  -s, --source          provide if the file is c source code
  -r, --raw             store binary in memory without encrypting
  -k KEY, --key KEY     key to encrypt with, randomly generated if not
                        supplied
  -o OUTFILE, --outfile OUTFILE
                        name of outfile, if not provided then random filename
                        is assigned
```

## Usage

- Generate and undetectable version of a pe executable using multiple layers of encryption

        ./darkarmour meterpreter.exe -o meter.exe

- Execute shellcode (x86/64) inside memory without detection, just provide the raw shellcode

        ./darkarmour -S meterpreter.bin -o meter.exe

## TODO

  - Intergrate into PowerUp
  - Add support for flags s,r,k
  - Run shellcode option, use dll inject to do it in diffrent process
  - Load pe image over a socket so not stored inside the binary
