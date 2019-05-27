#!/bin/bash

type=$1
executable=$2
filename=$3
finalexename=$4

if [ $# != 4 ]; then
  echo -e "Usage:\n"
  echo -e "$0 <type> <executable> <filename> <exename>\n"
  echo -e "type    \t- [exe] or [source] code"
  echo -e "executable\t- locating of source code, must be single file"
  echo -e "filename\t- filename of compiled source code"
  echo -e "exeneame\t- name of final packed file\n"
  exit
fi

if [ $type == "source" ]; then
  #do compile
  echo "compiling $executable..."
  i686-w64-mingw32-gcc $executable -o $filename -static
  echo "compiled to $filename"
  filesize=`wc -c $filename | grep -Eo '[0-9]' | xargs echo -n | sed 's/ //g'`
  echo "file size is $filesize bytes"
  echo "stripping..."
  strip $filename
  new_filesize=`wc -c $filename | grep -Eo '[0-9]' | xargs echo -n | sed 's/ //g'`
  echo "new file size is $new_filesize bytes"
fi;

#extract bytes
echo "extracting bytes..."
extract_area/bin2hex --i $filename --o extract_area/raw_bytes > /dev/null
rm pe_image.h
touch pe_image.h
cat extract_area/raw_bytes | ./extract_area/encrypt.py --count >> pe_image.h
echo -e "unsigned long long image_crypt[] = {" >> pe_image.h
cat extract_area/raw_bytes | ./extract_area/encrypt.py >> pe_image.h
echo -e "\n};" >> pe_image.h
echo "wrote bytes"


#compile launcher
#rm $filename
i686-w64-mingw32-g++ exec_memory.cpp main.cpp -o $finalexename -static
