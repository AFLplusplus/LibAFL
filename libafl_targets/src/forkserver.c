#include "common.h"

#include "android-ashmem.h"
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

// Set by this macro
// https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-cc.c#L993

int __afl_sharedmem_fuzzing __attribute__((weak));

extern uint8_t *__afl_area_ptr;
extern size_t   __afl_map_size;
extern uint8_t *__token_start;
extern uint8_t *__token_stop;

uint8_t        *__afl_fuzz_ptr;
static uint32_t __afl_fuzz_len_local;
uint32_t       *__afl_fuzz_len = &__afl_fuzz_len_local;

int already_initialized_shm;
int already_initialized_forkserver;

static int child_pid;
static void (*old_sigterm_handler)(int) = 0;

static uint8_t is_persistent;

void __afl_set_persistent_mode(uint8_t mode) {
  is_persistent = mode;
}

/* Error reporting to forkserver controller */

static void send_forkserver_error(int error) {
  uint32_t status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) { return; }
}

/* Ensure we kill the child on termination */

static void at_exit(int signal) {
  (void)signal;

  if (child_pid > 0) {
    kill(child_pid, SIGKILL);
    child_pid = -1;
  }

  _exit(0);
}

/* SHM fuzzing setup. */

void __afl_map_shm(void) {
  if (already_initialized_shm) return;
  already_initialized_shm = 1;

  char *id_str = getenv(SHM_ENV_VAR);

  if (id_str) {
#ifdef USEMMAP
    const char    *shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
    if (shm_fd == -1) {
      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    close(shm_fd);
    shm_fd = -1;

    if (shm_base == MAP_FAILED) {
      fprintf(stderr, "mmap() failed\n");
      perror("mmap for map");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);
    }

    __afl_area_ptr = shm_base;
#else
    uint32_t shm_id = atoi(id_str);
    __afl_area_ptr = (uint8_t *)shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (!__afl_area_ptr || __afl_area_ptr == (void *)-1) {
      send_forkserver_error(FS_ERROR_SHMAT);
      perror("shmat for map");
      exit(1);
    }

#endif

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;
  } else {
    fprintf(stderr,
            "Error: variable for edge coverage shared memory is not set\n");
    send_forkserver_error(FS_ERROR_SHM_OPEN);
    exit(1);
  }
}

static void map_input_shared_memory() {
  char *id_str = getenv(SHM_FUZZ_ENV_VAR);

  if (id_str) {
    uint8_t *map = NULL;

#ifdef USEMMAP
    const char *shm_file_path = id_str;
    int         shm_fd = -1;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, DEFAULT_PERMISSION);
    if (shm_fd == -1) {
      fprintf(stderr, "shm_open() failed for fuzz\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    map = (uint8_t *)mmap(0, MAX_FILE + sizeof(uint32_t), PROT_READ, MAP_SHARED,
                          shm_fd, 0);

#else
    uint32_t shm_id = atoi(id_str);
    map = (uint8_t *)shmat(shm_id, NULL, 0);

#endif

    /* Whooooops. */

    if (!map || map == (void *)-1) {
      perror("Could not access fuzzing shared memory");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    __afl_fuzz_len = (uint32_t *)map;
    __afl_fuzz_ptr = map + sizeof(uint32_t);

  } else {
    fprintf(stderr, "Error: variable for fuzzing shared memory is not set\n");
    send_forkserver_error(FS_ERROR_SHM_OPEN);
    exit(1);
  }
}

/* Fork server logic. */

void __afl_start_forkserver(void) {
  if (already_initialized_forkserver) return;
  already_initialized_forkserver = 1;

  struct sigaction orig_action;
  sigaction(SIGTERM, NULL, &orig_action);
  old_sigterm_handler = orig_action.sa_handler;
  signal(SIGTERM, at_exit);

  uint8_t  tmp[4] = {0, 0, 0, 0};
  uint32_t status_for_fsrv = 0;
  uint32_t already_read_first = 0;
  uint32_t was_killed;

  uint8_t child_stopped = 0;

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE) {
    status_for_fsrv |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  }

  int autodict_on = __token_start != NULL && __token_stop != NULL;
  if (autodict_on) { status_for_fsrv |= FS_OPT_AUTODICT; }

  if (__afl_sharedmem_fuzzing != 0) { status_for_fsrv |= FS_OPT_SHDMEM_FUZZ; }
  if (status_for_fsrv) { status_for_fsrv |= FS_OPT_ENABLED; }

  memcpy(tmp, &status_for_fsrv, 4);

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) { return; }

  if (__afl_sharedmem_fuzzing || autodict_on) {
    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) ==
        (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {
      map_input_shared_memory();
    }

    if ((was_killed & (FS_OPT_ENABLED | FS_OPT_AUTODICT)) ==
            (FS_OPT_ENABLED | FS_OPT_AUTODICT) &&
        autodict_on) {
      // great lets pass the dictionary through the forkserver FD
      uint32_t len = (__token_stop - __token_start), offset = 0;

      if (write(FORKSRV_FD + 1, &len, 4) != 4) {
        write_error("could not send dictionary len");
        _exit(1);
      }

      while (len != 0) {
        int32_t ret;
        ret = write(FORKSRV_FD + 1, __token_start + offset, len);

        if (ret < 1) {
          write_error("could not send dictionary");
          _exit(1);
        }

        len -= ret;
        offset += ret;
      }

    } else {
      // uh this forkserver does not understand extended option passing
      // or does not want the dictionary
      if (!__afl_fuzz_ptr) already_read_first = 1;
    }
  }

  while (1) {
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (already_read_first) {
      already_read_first = 0;

    } else {
      if (read(FORKSRV_FD, &was_killed, 4) != 4) {
        // write_error("read from afl-fuzz");
        _exit(1);
      }
    }

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) {
        write_error("child_stopped && was_killed");
        _exit(1);
      }
    }

    if (!child_stopped) {
      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) {
        write_error("fork");
        _exit(1);
      }

      /* In child process: close fds, resume execution. */

      if (!child_pid) {
        //(void)nice(-20);

        signal(SIGCHLD, old_sigchld_handler);
        signal(SIGTERM, old_sigterm_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
      }

    } else {
      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;
    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      write_error("write to afl-fuzz");
      _exit(1);
    }

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) {
      write_error("waitpid");
      _exit(1);
    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      write_error("writing to afl-fuzz");
      _exit(1);
    }
  }
}
