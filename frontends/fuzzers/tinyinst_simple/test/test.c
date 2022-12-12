#include <stdio.h>

void pass1(char *buf, int buf_size) {
  char target[0x10];
  if (buf[0] == 'b') {
    if (buf[1] == 'a') {
      if (buf[2] == 'd') {
        if (buf[3] == '1') {
          if (buf[4] == '2') {
            printf("You got me\n");
            memcpy(target, buf, 0x1000000);
            printf("GG\n");
          }
        }
      }
    }
  }
}
int main(int argc, char *argv[]) {
  FILE *fp;
  char  buf[0x1000];
  if (argc == 2) {
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
      printf("File not found\n");
      printf("Received filename %s\n", argv[1]);
      return 1;
    }
    fscanf(fp, "%s", buf);

    pass1(buf, sizeof(buf));

  } else {
    printf("there is nothing\n");
  }
}
