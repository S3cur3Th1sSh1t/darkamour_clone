#include <windows.h>
#include <stdio.h>

int main(int argc, char const *argv[]) {
  system("powershell /c ls");
  printf("%s\n", "pwned!!!");
  system("pause");
  return 0;
}
