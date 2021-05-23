#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){

    if(argc != 2){
        printf("Give me one input!\n");
        exit(0);
    }

    if(argv[1][0] == 'v'){
        if(argv[1][1] == 'u'){
            if(argv[1][2] == 'l'){
                if(argv[1][3] == 'n'){
                    abort();
                }
            }
        }
    }

    return 0;
}
