int main() {
  char *data = (char *)0x8000;
  // Extract the input from the memory at 0x8000
  char a = data[0];
  char b = data[1];
  char c = data[2];
  char result = 0;  // The result, so should be initialized at 0;

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

  return result;
}
