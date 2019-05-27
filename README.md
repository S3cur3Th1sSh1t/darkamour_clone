# Windows Binary Crypter

Store and execute an encrypted windows binary from inside memory, without a single bit touching disk.

## Usage

```
Windows crypter by Dylan Halls (v0.1)

usage: crypter.py [-h] [-u] [-b] [-s] [-r] [-k KEY] [-o OUTFILE] file

positional arguments:
  file                  file to crypt, assumed as binary if not told otherwise

optional arguments:
  -h, --help            show this help message and exit
  -u, --upx             upx file before crypting
  -b, --binary          provide if file is a binary exe
  -s, --source          provide if the file is c source code
  -r, --raw             store binary in memory without encrypting
  -k KEY, --key KEY     key to encrypt with, randomly generated if not
                        supplied
  -o OUTFILE, --outfile OUTFILE
                        name of outfile, if not provided then random filename
                        is assigned
```

## Example

`./crypter.py example.exe -o crypted_example.exe`

## TODO

  - Add support for flags u,s,r,k
  - DLL injection option to take over remote process
  - Load pe image over a socket so not stored inside the binary
