#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size >= 8 && *(uint32_t *)Data == 0xaabbccdd) { abort(); }
  char buf[8] = {'a', 'b', 'c', 'd'};

  if (Size == 10) {
    char choice = *(uint8_t *)Data[3];
    switch (choice) {
      case 1:
        choice += (rand() & 0x114);
        printf("You selected case 1. %d\n", choice);
        break;
      case 2:
        choice += (rand() & 0x112);
        printf("You selected case 2 %d.\n", choice);
        break;
      case 3:
        printf("You selected case 3.\n");
        break;
      case 4:
        printf("You selected case 4.\n");
        break;
      case 5:
        printf("You selected case 5.\n");
        break;
      case 6:
        printf("You selected case 6.\n");
        break;
      case 7:
        printf("You selected case 7.\n");
        break;
      case 8:
        printf("You selected case 8.\n");
        break;
      case 9:
        printf("You selected case 9.\n");
        break;
      case 10:
        printf("You selected case 10.\n");
        break;
      case 11:
        printf("You selected case 11.\n");
        break;
      case 12:
        printf("You selected case 12.\n");
        break;
      case 13:
        printf("You selected case 13.\n");
        break;
      default:
        printf("Invalid choice!\n");
        break;
    }
  }
  if (memcmp(Data, buf, 4) == 0) { abort(); }
  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
