#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){

    FILE* file = stdin;
    if (argc > 1) {
        file = fopen(argv[1], "rb");
    }

    char buf[16];
    char* p = fgets(buf, 16, file);
    buf[15] = 0;
    
    printf("input: %s\n", p);
    
    if(buf[0] == 'b'){
        if(buf[1] == 'a'){
            if(buf[2] == 'd'){
                abort();
            }
        }
    }

    return 0;
}
