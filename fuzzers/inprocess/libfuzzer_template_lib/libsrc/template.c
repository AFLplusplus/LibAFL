#include "template.h"

int template_run_some_data(char *data, size_t size) {

    if (data[0] == 'a') {
        if (data[1] == 'b') {
            if (data[2] == 'c') {
                abort();
            }
            return 3;
        }
        return 2;
    }

    return 1;
}