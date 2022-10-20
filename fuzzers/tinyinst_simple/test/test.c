#include <stdio.h>
#include <signal.h>

void pass1(char *gg) {
  char buf[10];
  if (gg[0] == 'b') {
    if (gg[1] == 'a') {
      if (gg[2] == 'd') {
        if (gg[3] == '1') {
          if (gg[4] == '2') {
            printf("You got me\n");
            memcpy(buf, gg, 100000);
          }
        }
      }
    }
  }
}
int main(int argc, char *argv[]) {
  if (argc == 2) {
    pass1(argv[1]);
  } else {
    printf("there is nothing\n");
  }
}
