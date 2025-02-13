int main() {
  char *data = (char *)0x8000;
  char  a = data[0];  // = 0x1;
  char  b = data[1];  // = 0x0;
  char  c = data[2];
  char  result = 0;  // The result, so should be initialized at 0;

  if (a > b) {
    result = 0x2;
    if (a > 0x20) {
      result = 0x3;
      if (a == 0x50) {
        result = 0x4;
        if (b == 0x24) {
          result = 0x5;
          if (c == 0x36) { result = 0x6; }
        }
      }
    }
  }

  /*
  a = 0xDE;
  b = 0xEA;
  c = 0xBE;
  */
  return result;
}
