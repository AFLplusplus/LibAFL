#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){


    sleep(0.1);
    char buf[16];
    fgets(buf, 16, stdin);
    if(buf[0] == 'b'){
        if(buf[1] == 'a'){
            if(buf[2] == 'd'){
                abort();
            }
        }
    }

    return 0;
}
