#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){

    char buf[16];
    char* p = fgets(buf, 16, stdin);
    buf[15] = 0;
    
    // printf("input: %s\n", p);
    
    if(buf[0] == 'b'){
        if(buf[1] == 'a'){
            if(buf[2] == 'd'){
                abort();
            }
        }
    }

    return 0;
}
