#include <stdio.h>

void pass1(char *gg) {
  if (gg[0] == 'b') {
    if (gg[1] == 'a') {
      if (gg[2] == 'd') {
        if (gg[3] == '1') {
          if (gg[4] == '2') { printf("You got me\n"); }
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
