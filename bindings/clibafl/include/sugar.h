#ifndef CLIBAFL_SUGAR_H
#define CLIBAFL_SUGAR_H

#include <stdlib.h>
#include <stdint.h>

typedef struct InMemoryBytesCoverageSugar {
    char** input_dirs;
    size_t input_dirs_len;
    char* output_dir;
    unsigned short broker_port;
    size_t* cores;
    size_t cores_len;
} InMemoryBytesCoverageSugar;

typedef void (*HarnessFunction)(uint8_t*, size_t);

InMemoryBytesCoverageSugar libafl_sugar_InMemoryBytesCoverageSugar_new(char** input_dirs, char* output_dir, unsigned short broker_port, size_t* cores);

void libafl_sugar_InMemoryBytesCoverageSugar_run(InMemoryBytesCoverageSugar* self, HarnessFunction harness);

#endif
