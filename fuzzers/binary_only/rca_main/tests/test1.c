#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main() {
    unsigned char buffer[16]; // A buffer to hold the 16 bytes
    // Read exactly 16 bytes from stdin
    size_t bytesRead = fread(buffer, 1, 16, stdin);
	// printf("%s\n", buffer);
	if (buffer[0] == 'a') {
		if (buffer[1] == 'b') {
			if (buffer[2] == 'c') {
				if(buffer[3] == 'd') {
					abort();
				}
			}
		}
	}
    return 0;
}
