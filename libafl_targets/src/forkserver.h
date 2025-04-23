#ifndef FORKSERVER_H
#define FORKSERVER_H

#include "common.h"

#include "android-ashmem.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifndef USEMMAP
  #include <sys/shm.h>
#else
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>

#define write_error(s) \
  fprintf(stderr, "Error at %s:%d: %s\n", __FILE__, __LINE__, s)

// AFL++ constants
#define FORKSRV_FD 198
#define MAX_FILE (1024 * 1024)
#define SHMEM_FUZZ_HDR_SIZE 4
#define SHM_ENV_VAR "__AFL_SHM_ID"
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define DEFAULT_PERMISSION 0600

/* Reporting errors */
#define FS_OPT_ERROR 0xf800008f
#define FS_OPT_GET_ERROR(x) ((x & 0x00ffff00) >> 8)
#define FS_OPT_SET_ERROR(x) ((x & 0x0000ffff) << 8)
#define FS_ERROR_MAP_SIZE 1
#define FS_ERROR_MAP_ADDR 2
#define FS_ERROR_SHM_OPEN 4
#define FS_ERROR_SHMAT 8
#define FS_ERROR_MMAP 16
#define FS_ERROR_OLD_CMPLOG 32
#define FS_ERROR_OLD_CMPLOG_QEMU 64

#define FS_NEW_VERSION_MAX 1
#define FS_NEW_OPT_MAPSIZE 0x1
#define FS_NEW_OPT_SHDMEM_FUZZ 0x2
#define FS_NEW_OPT_AUTODICT 0x800

/* Reporting options */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SNAPSHOT 0x20000000
#define FS_OPT_AUTODICT 0x10000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_NEWCMPLOG 0x02000000
#define FS_OPT_OLD_AFLPP_WORKAROUND 0x0f000000
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
#define FS_OPT_MAX_MAPSIZE ((0x00fffffeU >> 1) + 1)
#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) \
  (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

extern uint8_t *__afl_area_ptr;
extern size_t   __afl_map_size;
extern uint8_t *__token_start;
extern uint8_t *__token_stop;
extern uint8_t *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

struct libafl_forkserver_hook {
    void* data;
    void (*pre_fork_hook)(void* data);
    void (*post_parent_fork_hook)(void* data, pid_t child_pid);
    void (*post_child_fork_hook)(void* data);
    void (*pre_parent_wait_hook)(void* data);
    void (*post_parent_wait_hook)(void* data, pid_t wait_pid, int status);
};

/* Set persistent mode. */
void __libafl_set_persistent_mode(uint8_t mode);

/* SHM fuzzing setup. */
void __libafl_map_shm(void);

/* Fork server logic. */
void __libafl_start_forkserver(void);

/* Fork server logic, with hooks */
void __libafl_start_forkserver_with_hooks(struct libafl_forkserver_hook* hook);

#endif