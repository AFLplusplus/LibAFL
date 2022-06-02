#include <stdlib.h>
#include <stdio.h>

extern void start_forkserver(void);
extern void edges_map_ptr_from_env(void);

__attribute__((constructor())) void __forkserver_init(void) {
  char *env = getenv("LIBAFL_START_FORKSERVER");
  if (env) {
    edges_map_ptr_from_env();
    start_forkserver();
  }
}