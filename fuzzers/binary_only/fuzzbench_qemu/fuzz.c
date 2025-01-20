#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Data[0] == 'a') {
	if (Data[1] == 'b') {
	  if (Data[2] == 'c') {
		if (Data[3] == 'd'){
		  abort();		
	    }
	  }
	}
  }

  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
